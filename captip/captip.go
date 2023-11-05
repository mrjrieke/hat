package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrjrieke/hat/cap"
)

func featherCtl(pense string) {
	flapMode := cap.MODE_GAZE
	ctlFlapMode := flapMode
	var err error = errors.New("init")

	for {
		if err == nil && ctlFlapMode == cap.MODE_GLIDE {
			break
		} else {
			callFlap := flapMode
			if err == nil {
				if strings.HasPrefix(ctlFlapMode, cap.MODE_FLAP) {
					ctl := strings.Split(ctlFlapMode, "_")
					if len(ctl) > 1 {
						fmt.Printf("%s.", ctl[1])
					}
					callFlap = cap.MODE_GAZE
				} else {
					callFlap = cap.MODE_GAZE
				}
				time.Sleep(200 * time.Millisecond)
			} else {
				if err.Error() != "init" {
					fmt.Println("Waiting...")
					time.Sleep(1 * time.Second)
					callFlap = cap.MODE_GAZE
				}
			}
			ctlFlapMode, err = cap.FeatherCtlEmit("Som18vhjqa72935h", "1cx7v89as7df89", "127.0.0.1:1832", "ThisIsACode", callFlap, "HelloWorld")
		}
	}
}

func main() {
	fmt.Printf("\nFirst run\n")
	featherCtl("HelloWorld")
	fmt.Printf("\nResting....\n")
	time.Sleep(20 * time.Second)
	fmt.Printf("\nTime for work....\n")
	fmt.Printf("\n2nd run\n")
	featherCtl("HelloWorld")
}
