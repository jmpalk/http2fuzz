// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
//
// forked from https://github.com/c0nrad/http2fuzz and 
// 	modified by Justin Palk
package replay

import ( 
	"os"
	"time"
	"bufio"
	"fmt"
	"golang.org/x/net/http2"
	"github.com/jmpalk/http2fuzz/util"
	"github.com/jmpalk/http2fuzz/config"
)



var ReplayWriteFile *os.File
var ReplayReadFile *os.File

func init() {
	if config.ReplayMode == false {
		//ReplayWriteFile = OpenWriteFile("replay.json")
		if _, err := os.Stat(config.ReplayWriteFilename); os.IsNotExist(err) {
			ReplayWriteFile = OpenWriteFile(config.ReplayWriteFilename)
		} else {
			fmt.Printf("### File %s exists. Exiting ###\n", config.ReplayWriteFilename)
			os.Exit(-1)
		}
	}
	//ReplayReadFile = OpenReadFile("replay.json")
	ReplayReadFile = OpenReadFile(config.ReplayReadFilename)
}

type ReplayHandler struct {
	ReplayFile *os.File
}

func OpenWriteFile(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	return f
}

func OpenReadFile(filename string) *os.File{
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return f
}

func TruncateFile() {
	ReplayWriteFile.Truncate(0)
	ReplayWriteFile.Seek(0, 0)
}

func ReadFromReplayFile() ([]string){
	var data []string
	scanner := bufio.NewScanner(ReplayReadFile)

	for scanner.Scan() {
		data = append(data, scanner.Text())
	}
	return data
}

func WriteToReplayFile(data []byte) {
	data = append(data, '\n')
	_, err := ReplayWriteFile.Write(data)
	if err != nil {
		panic(err)
	}
	ReplayWriteFile.Sync()
}

func SaveRawFrame(frameType, flags uint8, streamID uint32, payload []byte) {
	frame := map[string]interface{}{
		"FrameMethod": "RawFrame",
		"FrameType":   frameType,
		"Flags":       flags,
		"StreamID":    streamID,
		"Payload":     util.ToBase64(payload),
		"Time":				 time.Now(),
	}

	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveWindowUpdateFrame(streamID, incr uint32){
	frame := map[string]interface{}{
		"FrameMethod": "WindowUpdateFrame",
		"StreamID":	streamID,
		"Incr":		incr,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveResetFrame(streamID, errorCode uint32){
	frame := map[string]interface{}{
		"FrameMethod": "ResetFrame",
		"StreamID":	streamID,
		"ErrorCode":	errorCode,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SavePriorityFrame(streamID, streamDep uint32, weight uint8, exclusive bool){
	frame := map[string]interface{}{
		"FrameMethod": 	"PriorityFrame",
		"StreamID":	streamID,
		"StreamDep":	streamDep,
		"Weight":	weight,
		"Exclusive":	exclusive,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveWriteContinuationFrame(streamID uint32, endStream bool, data []byte){
	frame := map[string]interface{}{
		"FrameMethod":	"WriteContinuationFrame",
		"StreamID":	streamID,
		"EndStream":	endStream,
		"Data":		data,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SavePushPromiseFrame(streamID, promiseID uint32, blockFragment []byte, endHeaders bool, padLength uint8){
	frame := map[string]interface{}{
		"FrameMethod":		"PushPromiseFrame",
		"StreamID":		streamID,
		"PromiseID":		promiseID,
		"BlockFragment":	blockFragment,
		"EndHeaders":		endHeaders,
		"PadLength":		padLength,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveDataFrame(streamID uint32, endStream bool, data []byte){
	frame := map[string]interface{}{
		"FrameMethod":		"DataFrame",
		"StreamID":		streamID,
		"EndStream":		endStream,
		"Data":			data,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}

func SaveSettingsFrame(settings []http2.Setting){
	frame := map[string]interface{}{
		"FrameMethod":	"SettingsFrame",
		"Settings":	settings,
		"Time":				 time.Now(),
		}
	out := util.ToJSON(frame)
	WriteToReplayFile(out)
}
