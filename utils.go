package main

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func TickerContext(ctx context.Context, duration time.Duration) <-chan time.Time {
	ticker := time.NewTicker(duration)
	go func() {
		<-ctx.Done()
		ticker.Stop()
	}()
	return ticker.C
}

// compareVersion compares two version strings
// returns -1 if v1 < v2, 1 if v1 > v2, 0 otherwise.
func compareVersion(v1, v2 string) int {
	var (
		currTab  = strings.Split(v1, ".")
		otherTab = strings.Split(v2, ".")
	)

	max := len(currTab)
	if len(otherTab) > max {
		max = len(otherTab)
	}
	for i := 0; i < max; i++ {
		var currInt, otherInt int

		if len(currTab) > i {
			currInt, _ = strconv.Atoi(getHeadDigits(currTab[i]))
		}
		if len(otherTab) > i {
			otherInt, _ = strconv.Atoi(getHeadDigits(otherTab[i]))
		}
		if currInt > otherInt {
			return 1
		}
		if otherInt > currInt {
			return -1
		}
	}
	return 0
}

// getHeadDigits returns the digit part at the beginning of a sting
func getHeadDigits(raw string) string {
	for idx, r := range raw {
		if !unicode.IsDigit(r) {
			return raw[:idx]
		}
	}
	return raw
}

// versionGreaterThan checks if a version is greater than another
func versionGreaterThan(v, other string) bool {
	return compareVersion(v, other) == 1
}
