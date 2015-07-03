package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
)

type LogEntry struct {
	pc uint32
}

type FileDefinition struct {
	filename string
}

type FunctionDefinition struct {
	name string
	file FileDefinition
}

type LineDefinition struct {
	lineNum  int
	function FunctionDefinition
}

type LineStatistics struct {
	smallestAddress uint32
	count           uint32
}

type AddressDefinition struct {
	address uint32
}

type EntityStatistics struct {
	count uint32
}

type ProfileStats struct {
	addresses map[AddressDefinition]EntityStatistics
	lines     map[LineDefinition]LineStatistics
	functions map[FunctionDefinition]EntityStatistics
	files     map[FileDefinition]EntityStatistics

	overall EntityStatistics
}

var options struct {
	raw         bool
	logFilename string
	exeFilename string
}

func parseProfileLog(log io.Reader, output chan *LogEntry) {
	var (
		lastEntry *LogEntry
	)

	reader := bufio.NewReader(log)

	for {
		c, err := reader.ReadByte()

		// Do we have a frame ending here?
		if lastEntry != nil {
			// Only accept the last frame if it ends properly - either at the end of the file or at the beginning of a new frame
			if err != nil || c == '>' {
				output <- lastEntry
			}

			lastEntry = nil
		}

		// Find a frame start character

		if err != nil {
			// File's finished
			break
		}

		if c != '>' {
			// Skip over garbage to find the next frame
			continue
		}

		// Read the frame
		lastEntry = &LogEntry{}
		if err := binary.Read(reader, binary.LittleEndian, &lastEntry.pc); err != nil {
			break
		}
	}

	// Signal completion
	output <- nil
}

func groupAddresses(queue chan *LogEntry) map[uint32]uint32 {
	addresses := make(map[uint32]uint32)
	totalObservations := 0

	// Count occurances of addresses
	for entry := range queue {
		if entry == nil {
			break
		}

		addresses[entry.pc]++
		totalObservations++
	}

	return addresses
}

func printRawAddresses(queue chan *LogEntry) {
	for entry := range queue {
		if entry == nil {
			break
		}

		fmt.Printf("0x%08x\n", entry.pc)
	}
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func parseLineInfo(addressCounts map[uint32]uint32, pipe io.Reader, stats *ProfileStats, done chan bool) {
	scanner := bufio.NewScanner(pipe)

	filenameLineSplit, _ := regexp.Compile("^(.+):(\\d+|\\?+)$")
	pathPrefixRemove, _ := regexp.Compile("^.*/\\./")

	for {
		var (
			address   uint32
			address64 uint64
		)

		if !scanner.Scan() {
			break
		}

		addressLine := scanner.Text()
		address64, err := strconv.ParseUint(addressLine, 0, 32)

		if err != nil {
			if len(addressLine) > 0 {
				fmt.Println(fmt.Sprintf("Bad address '%s', '%s'\n", addressLine, err))
			}
			break
		}

		address = uint32(address64)

		addressCount := addressCounts[address]

		if addressCount < 0 {
			panic(fmt.Sprintf("addr2line gave us an address 0x%08x which we didn't ask for, '%s'", address, addressLine))
		}

		scanner.Scan()
		functionName := scanner.Text()

		scanner.Scan()
		filenameLine := scanner.Text()

		matches := filenameLineSplit.FindStringSubmatch(filenameLine)

		if len(matches) < 2 {
			panic(fmt.Sprintf("Failed to parse filename/line number from '%s'\n", filenameLine, err))
		}

		filename := pathPrefixRemove.ReplaceAllString(matches[1], "")
		lineNum, err := strconv.ParseUint(matches[2], 10, 32)

		if err != nil {
			lineNum = 0
		}

		fileDef := FileDefinition{filename: filename}
		functionDef := FunctionDefinition{name: functionName, file: fileDef}
		lineDef := LineDefinition{function: functionDef, lineNum: int(lineNum)}
		addressDef := AddressDefinition{address: address}

		fileStats := stats.files[fileDef]
		fileStats.count += addressCount
		stats.files[fileDef] = fileStats

		functionStats := stats.functions[functionDef]
		functionStats.count += addressCount
		stats.functions[functionDef] = functionStats

		lineStats, ok := stats.lines[lineDef]
		if ok {
			lineStats.smallestAddress = minU32(lineStats.smallestAddress, address)
		} else {
			lineStats.smallestAddress = address
		}
		lineStats.count += addressCount
		stats.lines[lineDef] = lineStats

		addressStats := stats.addresses[addressDef]
		addressStats.count = addressCount
		stats.addresses[addressDef] = addressStats

		stats.overall.count += addressCount
	}

	done <- true
}

func translateAddressesToLineStats(addressCounts map[uint32]uint32) (result *ProfileStats) {
	result = &ProfileStats{
		addresses: make(map[AddressDefinition]EntityStatistics),
		lines:     make(map[LineDefinition]LineStatistics),
		functions: make(map[FunctionDefinition]EntityStatistics),
		files:     make(map[FileDefinition]EntityStatistics),
	}

	command := exec.Command("arm-none-eabi-addr2line", "--addresses", "--functions", fmt.Sprintf("--exe=%s", options.exeFilename))

	command.Stderr = os.Stderr
	stdinPipe, _ := command.StdinPipe()
	stdoutPipe, _ := command.StdoutPipe()

	err := command.Start()
	if err != nil {
		fmt.Printf("\nError: %s\nFailed to run 'arm-none-eabi-addr2line', is it on the $PATH?\n", err)
		return
	}

	// Start reading responses in parallel to avoid deadlock
	complete := make(chan bool)

	go parseLineInfo(addressCounts, stdoutPipe, result, complete)

	// Send all our requests out for address translation
	for address, _ := range addressCounts {
		io.WriteString(stdinPipe, fmt.Sprintf("0x%x\n", address))
	}
	stdinPipe.Close()

	// Wait for all the replies to get back
	<-complete

	stdoutPipe.Close()

	command.Wait()

	return
}

func parseCommandline() bool {
	flag.BoolVar(&options.raw, "raw", false, "Only print raw addresses, perform no analysis")
	flag.StringVar(&options.logFilename, "log", "", "Profile log file")
	flag.StringVar(&options.exeFilename, "elf", "cleanflight_NAZE.elf", "cleanflight_*.elf file that corresponds to the profile")

	flag.Parse()

	if len(options.logFilename) == 0 {
		fmt.Println("Missing log filename argument")
		return false
	}
	if len(options.exeFilename) == 0 {
		fmt.Println("Missing elf filename argument")
		return false
	}

	return true
}

type FileStatsPair struct {
	def   FileDefinition
	stats EntityStatistics
}

type FileStatsArray []FileStatsPair

func (x FileStatsArray) Len() int {
	return len(x)
}

func (x FileStatsArray) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}
func (x FileStatsArray) Less(i, j int) bool {
	return x[i].stats.count > x[j].stats.count
}

type FunctionStatsPair struct {
	def   FunctionDefinition
	stats EntityStatistics
}

type FunctionStatsArray []FunctionStatsPair

func (x FunctionStatsArray) Len() int {
	return len(x)
}

func (x FunctionStatsArray) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}
func (x FunctionStatsArray) Less(i, j int) bool {
	return x[i].stats.count > x[j].stats.count
}

type LineStatsPair struct {
	def   LineDefinition
	stats LineStatistics
}

type LineStatsArray []LineStatsPair

func (x LineStatsArray) Len() int {
	return len(x)
}

func (x LineStatsArray) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}
func (x LineStatsArray) Less(i, j int) bool {
	return x[i].stats.count > x[j].stats.count
}

func printLineStats(stats *ProfileStats, topN int) {
	var lines LineStatsArray

	fmt.Printf("Top %d lines by sample count:\n\n", topN)

	// Push the contents of the map into an array so we can sort them
	for def, stats := range stats.lines {
		lines = append(lines, LineStatsPair{def, stats})
	}

	sort.Sort(lines)

	// Print the top X entries by sample count
	for i := 0; i < len(lines) && i < topN; i++ {
		line := lines[i]
		fmt.Printf("[0x%08x] %s:%s:%d - %d samples (%.2f%%)\n", line.stats.smallestAddress, line.def.function.file.filename,
			line.def.function.name, line.def.lineNum, line.stats.count, float32(line.stats.count*100)/float32(stats.overall.count))
	}

	fmt.Println()
}

func printFunctionStats(stats *ProfileStats, topN int) {
	var functions FunctionStatsArray

	fmt.Printf("Top %d functions by sample count:\n\n", topN)

	// Push the contents of the map into an array so we can sort them
	for def, stats := range stats.functions {
		functions = append(functions, FunctionStatsPair{def, stats})
	}

	sort.Sort(functions)

	// Print the top X entries by sample count
	for i := 0; i < len(functions) && i < topN; i++ {
		function := functions[i]
		fmt.Printf("%s:%s - %d samples (%.2f%%)\n", function.def.file.filename,
			function.def.name, function.stats.count, float32(function.stats.count*100)/float32(stats.overall.count))
	}

	fmt.Println()
}

func printFileStats(stats *ProfileStats, topN int) {
	var files FileStatsArray

	fmt.Printf("Top %d files by sample count:\n\n", topN)

	// Push the contents of the map into an array so we can sort them
	for def, stats := range stats.files {
		files = append(files, FileStatsPair{def, stats})
	}

	sort.Sort(files)

	// Print the top X entries by sample count
	for i := 0; i < len(files) && i < topN; i++ {
		file := files[i]
		fmt.Printf("%s - %d samples (%.2f%%)\n", file.def.filename, file.stats.count,
			float32(file.stats.count*100)/float32(stats.overall.count))
	}

	fmt.Println()
}

func main() {
	if !parseCommandline() {
		return
	}

	log, err := os.Open(options.logFilename)
	if err != nil {
		fmt.Printf("Failed to open profile log file '%s'\n", options.logFilename)
		return
	}

	parsedDataChan := make(chan *LogEntry, 50)

	go parseProfileLog(log, parsedDataChan)

	if options.raw {
		printRawAddresses(parsedDataChan)
	} else {
		addressCounts := groupAddresses(parsedDataChan)

		stats := translateAddressesToLineStats(addressCounts)

		var maxResults int = 50

		fmt.Printf("%d samples in total\n\n", stats.overall.count)

		printLineStats(stats, maxResults)
		printFunctionStats(stats, maxResults)
		printFileStats(stats, maxResults)
	}
}
