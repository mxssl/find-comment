package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

var comments int
var inComment bool

func main() {
	file, err := os.Open("testdata.c")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	oneLineComment, err := regexp.Compile(`\v*\/\/`)
	if err != nil {
		panic(err)
	}
	multilineCommentStart, err := regexp.Compile(`.*/\*`)
	if err != nil {
		panic(err)
	}
	multilineCommentEnd, err := regexp.Compile(`.*\*\/`)
	if err != nil {
		panic(err)
	}

	for scanner.Scan() {
		text := scanner.Text()
		matchOneLineComment := oneLineComment.MatchString(text)
		if matchOneLineComment {
			comments++
			continue
		}

		matchMultiLineCommentStart := multilineCommentStart.MatchString(text)

		if matchMultiLineCommentStart {
			inComment = true
		}

		if inComment {
			comments++
		}

		matchMultiLineCommentEnd := multilineCommentEnd.MatchString(text)

		if matchMultiLineCommentEnd {
			inComment = false
		}
	}
	fmt.Println(comments)
}
