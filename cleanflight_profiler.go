package main

import (
	"bufio"
	"fmt"
	"os"
	"io"
	"encoding/binary"
)

type LogEntry struct {
	pc uint32
}

func parse(log io.Reader, output chan *LogEntry) {
	var (
		lastEntry *LogEntry
	)
	
	reader := bufio.NewReader(log)
	
	for {
		c, err := reader.ReadByte()
		
		// Do we have a frame ending here?
		if lastEntry != nil {
			// Only accept the last frame if it ends properly
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
			continue;
		}
		
		// Read the frame
		lastEntry = &LogEntry{}
		
		err = binary.Read(reader, binary.LittleEndian, &lastEntry.pc)
		
		if err != nil {
			lastEntry = nil
		}
	}
	
	output <- nil
}

func output(queue chan *LogEntry) {
	for entry := range queue {
		if entry == nil {
			break
		}
		 
		fmt.Printf("%d\n", entry.pc)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Missing input log file argument")
		return;
	}
	
	logFilename := os.Args[1];
	
	log, err := os.Open(logFilename)
	if (err != nil) {
		fmt.Printf("Failed to open profile log file '%s'\n", logFilename)
		return;
	}
	
	parsedDataChan := make(chan *LogEntry, 50)
	
	go parse(log, parsedDataChan)
	output(parsedDataChan)
}