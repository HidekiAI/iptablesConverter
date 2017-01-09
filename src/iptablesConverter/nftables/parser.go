package nftables

import (
	"log"
	"strconv"
	"strings"
)

// Nested block of texts either in braces as well as a single
// line of text with sub-statements
// Example 1: Block of text
//	table ip filter {
//		chain input {
//			type filter hook input priority 0; policy accept;
//			ip protocol tcp counter packets 0 bytes 0 # handle 2
//		}
//	}
// Example 2: Single line
//	table ip filter { chain input { type filter hook input priority 0; policy accept ; ip protocol tcp counter packets 0 bytes 0 } }
// In either of the example, the parent Line will be 'table ip filter', followed by
// its only child 'chain input', in which its children (grandchildren to root) are the 3
// lines ('type', 'policy', and 'ip')
type TTextStatement struct {
	// If the line consists of 'table ip filter { type filter hook forward priority 0; policy drop }'
	// Then:
	// 		Tokens = |table|ip|filter| (3 tokens)
	//		SubStatement[0].Tokens = |type|filter|hook|forward|priority|0;|
	//		SubStatement[1].Tokens = |policy|drop|
	// SubStatements can be nested
	Tokens       []string          // tokenized line (you can do things like 'strings.Join(Tokens, " ")')
	SubStatement []*TTextStatement // array of children blocks (i.e. 'table filter' has two children 'chain Input' and 'chain Output')
	Parent       *TTextStatement   // Mainly used during custructions to walk in/out of '{}' blocks (See MakeStatements() method)
}

// Strips out comments from a line, use this before you tokenize a line
func stripComment(line string) string {
	if strings.Contains(line, "\n") {
		log.Panicf("Cannot parse multiple lines in stripComment() method!\n")
	}
	if strings.Contains(line, "#") == false {
		// nothing to do, just return as-is
		return line
	}
	if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		// line starts with "#", return empty string
		return ""
	}

	// make sure to take account of '#' within the quoted text (i.e. '"this line has # in int" # my comment')
	// easiest way to deal with this is to tokenize the line, but combine/join quoted strings first
	split := tokenizeLineByQuotedText(line)

	//log.Printf("Parsing '%s' for comments..., TokenCount: %d\n", strings.Join(split, " "), len(split))
	iHash := len(split)
	for i, token := range split {
		//log.Printf("\tCurrent Token: '%s'\n", token)
		if strings.HasPrefix(token, "#") {
			iHash = i
			break
		}
	}
	// now we should be at the last '#' that is outside the quotes
	joinedText := strings.TrimSpace(strings.Join(split[:iHash], " "))
	//log.Printf("Strip comment Final: '%s'\n", joinedText))
	return joinedText
}

func splitWithKeyInPlace(s string, find string) []string {
	split := []string{s}
	if strings.Contains(s, find) {
		// we still need these tokens in place, replace it first with a marker
		tempStr := strings.Replace(s, find, " "+find+" ", -1)

		// look for it and split it
		split = strings.Split(tempStr, find)
		for si, ss := range split {
			s := strings.TrimSpace(ss)
			if s == "" {
				split[si] = find
			} else {
				split[si] = s
			}
		}
	}
	return split
}

// tokenize a line by spaces, but keep quoted strings (which may have spaces) as single token
// It is NOT meant to be used on block of text, in common usage, you want to call stripComment()
// first (i.e. tokens := tokenizeLineByQuotedText(stripComment(currentLine)))
func tokenizeLineByQuotedText(line string) []string {
	retStrList := []string{}

	split := strings.Fields(strings.Trim(line, " "))
	if len(split) > 0 {
		//log.Printf("Tokenizing '%+v'...", split)
		i := 0
		for i = 0; i < len(split); i++ {
			qStr, c := joinFieldsIfQuoted(split[i:])
			if c > 1 {
				i = i + c - 1 // subract 1 because the for{} will increment
			}
			retStrList = append(retStrList, qStr)
		}

		// see if it is multiple tokens without " " (i.e. 'priority 0;policy drop' -> 0;policy)
		for i := 0; i < len(retStrList); i++ {
			token := retStrList[i]
			if strings.HasPrefix(token, "\"") || strings.HasPrefix(token, "'") {
				// skip quoted strings
				continue
			}
			// ignore standalone tokens
			if token == ";" || token == "{" || token == "}" {
				continue
			}

			if strings.Contains(token, "{") {
				split := splitWithKeyInPlace(token, "{")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)

				// try again
				i--
				continue
			}
			if strings.Contains(token, "}") {
				split := splitWithKeyInPlace(token, "}")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)

				// try again
				i--
				continue
			}
			if strings.Contains(token, ";") {
				split := splitWithKeyInPlace(token, ";")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)

				// try again
				i--
				continue
			}
		}
		//log.Printf("\tDone tokenizing to %d tokens\n", len(retStrList))
	}
	return retStrList
}

// Provided with list of strings where strList[0] is or isn't a token which may or may not
// start with a quotation marks.  If it does start with one, it will join tokens until
// the closing quotation marks are found.  Which then will return the joined string and
// number of tokens it has consumed.
func joinFieldsIfQuoted(strList []string) (string, int) {
	retString := ""
	retCount := 0
	foundClosing := false
	// search for text which begins with \" and ends with matching punctuations
	// Note that nftables (unlike iptables?) are always based on double-quotes (") so
	// no need to distinquish differences of 'this string' versus "this string" and
	// no care needs to be taken for texts which has embedded quotes (i.e. "This shouldn't be split by 'single quotes'")
	// Also, because of tokenizing by whitespace, there is no need to consider cases where
	// a line contains something of 'comment"A comment"' (has to be 'comment "A comment"'), but
	// there is a special case of ";" which can be something of ';comment "trailing semi-colon";' thus
	// inspection of suffix needs to be cared for.
	if strings.HasPrefix(strList[0], "\"") || strings.HasPrefix(strList[0], "'") {
		punctuation := strList[0][:1]
		//log.Printf("\t\t\tJoinParsing quoted text '%+v' (punctuation: '%s')\n", strList, punctuation)
		retString = retString + strList[0] // including the punctuation
		retCount++
		// Check if a single field/word comment has ending quotes on the same word
		if strings.HasSuffix(strList[0], punctuation) || strings.HasSuffix(strList[0], punctuation+";") {
			foundClosing = true
		} else {
			for _, s := range strList[1:] {
				retCount++
				retString = retString + " " + s
				if strings.HasSuffix(s, punctuation) || strings.HasSuffix(s, punctuation+";") {
					// Let's be careful about escaped punctuations inside the string, for example
					// a string of '"This has \"double quotes\" in it"' would be tokenized as:
					//	["This], [has], [\"double], [quotes\"], [in], [it"]
					// in which case, we want the one with the [it"] and not the middle ones
					if strings.HasSuffix(s, "\\"+punctuation) || strings.HasSuffix(s, "\\"+punctuation+";") {
						continue
					}
					foundClosing = true
					break
				}
			}
		}

		if foundClosing == false {
			log.Panic("Unable to find closing quote in the string-list passed")
		}
	} else {
		// if no punctuations are found, assume next field is the ONLY string
		retString = strList[0]
		retCount++
	}
	// Could have probably done strings.Join(slice[:retCount], " ") here...
	//log.Printf("\t\t\t> Parsed '%s' (count: %d) from '%s'\n", retString, retCount, strList)
	if strings.HasSuffix(retString, ";") {
		retString = retString[:len(retString)-1]
	}
	return retString, retCount
}

func splitAndAppend(token string, find string, tokens []string, iToken int) []string {
	if strings.Contains(token, find) {
		// found one, so do some insertion
		split := strings.Split(token, find)

		// replace new collection of lines with current line
		// i.e. "foo; bar" (len=1) -> "foo" "bar" (len=2)
		// first, append the rest of the lines to new set of line
		var tail []string
		if (iToken + 1) > len(tokens) {
			// nothing trailing, just make this the tail
			tail = split
		} else {
			// append next line ... to end
			tail = append(split, tokens[iToken+1:]...)
		}
		// now cut current line, and append it
		tokens = append(tokens[:iToken], tail...)
	}
	return tokens
}

// breaks apart lines with ';' into two lines, and also takes into account quoted
// strings (in case the semi-colon is inside the quotes, which should not be split)
// At the same time, it will return multi-dimension to separte into blocks encountered
// by each encounter of '}' (it does not take account of whether the matching '{' were
// there)
func tokenizeMultiStatements(bodyOfText string) [][]string {
	log.Printf("Parsing:\n%s", bodyOfText)

	tokenizedLines := make([][]string, 0)

	// first, tokenize each lines (with comments removed)
	lines := strings.Split(bodyOfText, "\n")
	for lineNum, line := range lines {
		// first, strip out the comment from the line
		lines[lineNum] = stripComment(line)
	}

	// Now that comment has been stripped, join escaped lines

	// By here, each lines have been stripped of comments which may have texts that may
	// get misinterpreted (i.e. "#This line is not escaped because it is commented \")
	// Join multi-lines that are escaped into single line
	for lineNum, line := range lines {
		if len(line) == 0 {
			continue
		}

		if strings.HasSuffix(line, "\\") {
			// join current with next
			join := line[:len(line)-1] // stip off the trailing '\'
			lines[lineNum] = ""        // empty current
			if (lineNum + 1) < len(lines) {
				lines[lineNum+1] = join + " " + lines[lineNum+1]
			} else {
				lines[lineNum] = join
			}
		}

		// now tokenize this line
		tokens := tokenizeLineByQuotedText(lines[lineNum])
		if len(tokens) > 0 {
			tokenizedLines = append(tokenizedLines, tokens)
		}
	}

	// Now that escaped lines have been joined back, we need to next split any line which
	// contains ';' into another line
	indent := "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"
	indentIndex := 0
	for lineNum := 0; lineNum < len(tokenizedLines); lineNum++ {
		tokens := tokenizedLines[lineNum]
		lineStatement := "#" + strconv.Itoa(lineNum) + ": " + indent[:indentIndex]
		for iToken := 0; iToken < len(tokens); iToken++ {
			token := tokens[iToken]
			if token == "{" {
				indentIndex++
			}
			if token == "}" {
				indentIndex--
				if indentIndex < 0 {
					indentIndex = 0
				}
			}
			if token == "" {
				continue
			}
			if token == ";" {
				continue
			}
			if strings.HasPrefix(token, "\"") || strings.HasPrefix(token, "'") {
				// skip any token that is quoted text
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
				continue
			}
			if strings.Contains(token, ";") {
				// found one, so do some insertion
				tokenizedLines[lineNum] = splitAndAppend(token, ";", tokens, iToken)
				token = tokens[iToken]
			}
			lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
		}
		log.Printf(lineStatement)
	}

	return tokenizedLines
}

// Parses lines and whenever it encounters '{', it will branch off to a child (push)
// until it reaches the matching closing '}' (pop).
// if it detects embedded braces in between, it will add/push it as child and process lines
// until it reaches the popping/closing '}'.
// Encounter of ';' will signal next statement (multi-statements can be on single line)
// Encounter of '#' up to the EOL will be ignored/stripped
// Encounter of '\' at EOL (after the "#"..EOL is stripped) will join next line
// Assume that what is passed (the body) can be a slice, thus body[0] is assumed to be the current
// starting line to begin inspection.
/*
INPUT FILE FORMAT
	LEXICAL CONVENTIONS
		Input is parsed line-wise. When the last character of a line, just before the newline character, is a
		non-quoted backslash (\), the next line is treated as a continuation. Multiple commands on the same line
		can be separated using a semicolon (;).

		A hash sign (#) begins a comment. All following characters on the same line are ignored.

		Identifiers begin with an alphabetic character (a-z,A-Z), followed zero or more alphanumeric characters
		(a-z,A-Z,0-9) and the characters slash (/), backslash (\), underscore (_) and dot (.). Identifiers using
		different characters or clashing with a keyword need to be enclosed in double quotes (").

	INCLUDE FILES
		include filename

		Other files can be included by using the include statement.  The directories to be searched for include
		files can be specified using the -I/--includepath option.

	SYMBOLIC VARIABLES
		define variable expr
		$variable

		Symbolic variables can be defined using the define statement.  Variable references are expressions and can
		be used initialize other variables.  The scope of a definition is the current block and all blocks
		contained within.

		Using symbolic variables

		define int_if1 = eth0
		define int_if2 = eth1
		define int_ifs = { $int_if1, $int_if2 }

		filter input iif $int_ifs accept

*/
// Reads a block of text and splits, removes, or joins depending on:
//	* All characters from '#' to EOL (except when inside a quotation marks) will be stripped off
//	* Lines suffix with escape '\' character will be joined
//	* Lines with ';' will be split to multiple lines
func MakeStatements(textBody string) []TTextStatement {
	retStatements := make([]TTextStatement, 1)
	var pCurrentBlock *TTextStatement
	pCurrentBlock = &retStatements[0]

	// tokenizeMultiStatements basically returns blocks of []string
	tokenizedLines := tokenizeMultiStatements(textBody) // safety: this method won't split quoted text with semi-colons
	for _, line := range tokenizedLines {
		for _, token := range line {
			if token == "{" {
				newChild := TTextStatement{Parent: pCurrentBlock}
				pCurrentBlock.SubStatement = append(pCurrentBlock.SubStatement, &newChild)
				pCurrentBlock = &newChild
				continue
			}
			if token == "}" {
				pCurrentBlock = pCurrentBlock.Parent
				if pCurrentBlock == nil {
					// New block
					newBlock := TTextStatement{}
					retStatements = append(retStatements, newBlock)
					pCurrentBlock = &newBlock
				}
				// Prepare for next new statement
				newChild := TTextStatement{Parent: pCurrentBlock}
				if pCurrentBlock.Parent != nil {
					pCurrentBlock.Parent.SubStatement = append(pCurrentBlock.SubStatement, &newChild)
					pCurrentBlock = &newChild
				} else {
					pCurrentBlock.SubStatement = append(pCurrentBlock.SubStatement, &newChild)
					pCurrentBlock = &newChild
				}
				continue
			}

			pCurrentBlock.Tokens = append(pCurrentBlock.Tokens, token)
		}
	}
	return retStatements
}
