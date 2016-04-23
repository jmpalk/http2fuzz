// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
// Modified by Justin Palk
package fuzzer


import (
	"fmt"
	"time"
	"os"
	"golang.org/x/net/http2"
	"github.com/jmpalk/http2fuzz/config"
	"github.com/jmpalk/http2fuzz/util"
	"github.com/jmpalk/http2fuzz/replay"
)

func Client() {
	target := config.Target
	tls := config.IsTLS()
	restartFuzzer := true
	sendSettingsInit := true

	//added JMP 4-22-16
	replayMode := config.ReplayMode

	conn0 := NewConnection(target, tls, true, sendSettingsInit)

	if replayMode != false {
		var frames []string
		frames = replay.ReadFromReplayFile()
		RunReplay(conn0, frames)
		os.Exit(0)
	}


	fuzzer0 := NewFuzzer(conn0, restartFuzzer)
	go fuzzer0.PingFuzzer()

	conn1 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer1 := NewFuzzer(conn1, restartFuzzer)
	go fuzzer1.RawFrameFuzzer()

	conn2 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer2 := NewFuzzer(conn2, restartFuzzer)
	go fuzzer2.PriorityFuzzer()
	go fuzzer2.PingFuzzer()
	go fuzzer2.HeaderFuzzer()

	conn3 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer3 := NewFuzzer(conn3, restartFuzzer)
	go fuzzer3.PriorityFuzzer()
	go fuzzer3.PingFuzzer()
	go fuzzer3.HeaderFuzzer()
	go fuzzer3.WindowUpdateFuzzer()

	conn4 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer4 := NewFuzzer(conn4, restartFuzzer)
	go fuzzer4.PriorityFuzzer()
	go fuzzer4.PingFuzzer()
	go fuzzer4.HeaderFuzzer()
	go fuzzer4.ResetFuzzer()

	conn5 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer5 := NewFuzzer(conn5, restartFuzzer)
	go fuzzer5.SettingsFuzzer()
	go fuzzer5.HeaderFuzzer()

	conn6 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer6 := NewFuzzer(conn6, restartFuzzer)
	go fuzzer6.DataFuzzer()
	go fuzzer6.HeaderFuzzer()

	conn7 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer7 := NewFuzzer(conn7, restartFuzzer)
	go fuzzer7.ContinuationFuzzer()
	go fuzzer7.HeaderFuzzer()

	conn8 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer8 := NewFuzzer(conn8, restartFuzzer)
	go fuzzer8.PushPromiseFuzzer()
	go fuzzer8.HeaderFuzzer()

	conn9 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer9 := NewFuzzer(conn9, restartFuzzer)
	go fuzzer9.RawTCPFuzzer()

	conn10 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer10 := NewFuzzer(conn10, restartFuzzer)
	go fuzzer10.RawTCPFuzzer()

	conn11 := NewConnection(target, tls, false, !sendSettingsInit)
	fuzzer11 := NewFuzzer(conn11, restartFuzzer)
	go fuzzer11.RawTCPFuzzer()

	conn12 := NewConnection(target, tls, true, sendSettingsInit)
	fuzzer12 := NewFuzzer(conn12, restartFuzzer)
	go fuzzer12.PriorityFuzzer()
	go fuzzer12.PingFuzzer()
	go fuzzer12.HeaderFuzzer()
	go fuzzer12.PushPromiseFuzzer()
	go fuzzer12.ContinuationFuzzer()
	go fuzzer12.WindowUpdateFuzzer()
}

func RunReplay(c *Connection, frames []string) {
	for _, frameJSON := range frames {
 		frame := util.FromJSON([]byte(frameJSON))

 		if c.Err != nil {
 			fmt.Println("Connection Error", c.Err, "restarting connection")
 			c = NewConnection(config.Target, c.IsTLS, c.IsPreface, c.IsSendSettings)
 		}

 		switch frame["FrameMethod"] {
 		case "RawFrame":
 			fmt.Println(frame)
 			frameType := uint8(frame["FrameType"].(float64))
 			flags := uint8(frame["Flags"].(float64))
 			streamID := uint32(frame["StreamID"].(float64))
 			payload := util.FromBase64(frame["Payload"].(string))
 			c.WriteRawFrame(frameType, flags, streamID, payload)
 			time.Sleep(time.Second * 1)
		case "WindowUpdateFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
			incr := uint32(frame["Incr"].(float64))
			c.WriteWindowUpdateFrame(streamID, incr)
			time.Sleep(time.Second * 1)
		case "ResetFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
 			errorCode := uint32(frame["ErrorCode"].(float64))
			c.WriteResetFrame(streamID, errorCode)
			time.Sleep(time.Second * 1)
		case "PriorityFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
 			streamDep := uint32(frame["StreamDep"].(float64))
			weight := uint8(frame["Weight"].(float64))
			exclusive := bool(frame["Exclusive"].(bool))
			c.WritePriorityFrame(streamID, streamDep, weight, exclusive)
			time.Sleep(time.Second * 1)
		case "WriteContinuationFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
			endStream := bool(frame["EndStream"].(bool))
 			data := util.FromBase64(frame["Data"].(string))
			c.WriteContinuationFrame(streamID, endStream, data)
			time.Sleep(time.Second * 1)
		case "PushPromiseFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
 			promiseID := uint32(frame["PromiseID"].(float64))
 			blockFragment := util.FromBase64(frame["BlockFragment"].(string))
			endHeaders := bool(frame["EndHeaders"].(bool))
			padLength := uint8(frame["PadLength"].(float64))
			promise := http2.PushPromiseParam{streamID, promiseID, blockFragment, endHeaders, padLength}
			c.WritePushPromiseFrame(promise)
			time.Sleep(time.Second * 1)
		case "DataFrame":
			fmt.Println(frame)
 			streamID := uint32(frame["StreamID"].(float64))
			endStream := bool(frame["EndStream"].(bool))
			data := util.FromBase64(frame["Data"].(string))
			c.WriteDataFrame(streamID, endStream, data)
			time.Sleep(time.Second * 1)
		case "SettingsFrame":
			var settings []http2.Setting

			m := frame["Settings"].([]interface{})
			for _, v := range m{
				switch vv := v.(type) {
					case map[string]interface{}:
						var ID uint16
						var Value uint32
						for i, u := range vv {
							if string(i) == "ID" {
								ID = uint16(u.(float64))
							} else if string(i) == "Val" {
								Value = uint32(u.(float64))
							}
						}
						settings = append(settings, http2.Setting{http2.SettingID(ID), Value})
					}
				}
			c.WriteSettingsFrame(settings)
			time.Sleep(time.Second * 1)

 		}
 	}
 	fmt.Println("ALL DONE")
 }
