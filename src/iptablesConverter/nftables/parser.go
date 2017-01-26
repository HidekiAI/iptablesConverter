package nftables

import (
	"fmt"
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
	Depth        uint16            // mainly for debugging and printing, but can be used to determine siblings
}

// TODO: Use type TToken and CToken* for consistencies in the future

const tabs = "|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|"

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
		// i.e. line such as 'Root{child1{child2' would become 'Root { child1 { child2'
		tempStr := strings.Replace(s, find, " "+find+" ", -1)
		// now split by space
		split = strings.Fields(tempStr)
	}
	return split
}
func splitNonWhitespaced(tokens []string) []string {
	var retList []string
	for _, t := range tokens {
		// ignore any quoted string tokens
		if strings.HasPrefix(t, "\"") || strings.HasPrefix(t, "'") {
			retList = append(retList, t)
			continue
		}

		sO := splitWithKeyInPlace(t, "{")
		for _, sO1 := range sO {
			sC := splitWithKeyInPlace(sO1, "}")
			for _, sC1 := range sC {
				sSC := splitWithKeyInPlace(sC1, ";")
				for _, sSC1 := range sSC {
					retList = append(retList, sSC1)
				}
			}
		}
	}

	return retList
}
func splitAndRejoin(token string, find string, tokens []string, i int) []string {
	split := splitWithKeyInPlace(token, find)
	tail := append(split, tokens[i+1:]...)
	retStrList := append(tokens[:i], tail...)
	if (logLevel > 1) && (len(tokens) != len(retStrList)) {
		log.Printf("splitAndRejoin(Key='%s', Token='%s')\n\tAfter split count(%d) -> %+v\n\ttail(%d) -> %+v\n\t\tBefore(%2d):%+v\n\t\t After(%2d):%+v\n",
			find, token, len(split), split, len(tail), tail, len(tokens), tokens, len(retStrList), retStrList)
	}
	return retStrList
}

// if any tokens that are unquoted has the delimiter, then join it
// i.e. if tokens={"{", "a", ",", "b", ",", "c-d", ",", "e", "}"} (count=9), then
// we want the "a,b,c-d,e" to be a single token if search key is ",", so that result is:
// tokens={"{", "a,b,c-d,e", "}"} (count=3)
func joinDelimited(tokens []string, key string) []string {
	var retList []string
	start := 0
	stop := 0
	foundKey := false
	done := false
	i := 0
	for done == false {
		t := tokens[i]
		// see if it has been appended (i.e. 'a,' instead of 'a' and ',') as well
		// handles cases of ',' as standalone token, or ',a' and 'a,', and
		// because it is already tokenized, by just checking prefix and suffix,
		// we won't have issues of "'this string has a , in int'" but will
		// able to treat ',"string,1"' and '"string,2",' where the key is
		// at head or tail
		isToken := t == key
		hasPrefix := strings.HasPrefix(t, key)
		hasSuffix := strings.HasSuffix(t, key)
		if isToken || hasPrefix || hasSuffix {
			foundKey = true
			//log.Printf("\tFound %s at %d (in %+v)", t, i, tokens)
			if isToken || hasSuffix {
				// stop needs to be one after this
				stop = i + 1
			} else {
				// if found on prefix, it's part of the token, so make stop==current (this token)
				stop = i
			}

			// Q: Does it handle cases of 'a ,b, c'?
			if start == 0 {
				if isToken || hasPrefix {
					// start needs to happen on previous token if key found on current or as prefix
					if i > 0 {
						start = i - 1
					} else {
						start = 0
					}
				} else {
					// if occurrences is at the suffix, make this one to be the start
					start = i
				}
				stop = i + 1
			}
		}
		if foundKey && (start != stop) {
			// join them all with no whitespace between, so it becomes a single expression/token
			joined := strings.Join(tokens[start:stop+1], "")
			tail := []string{joined}
			tail = append(tail, tokens[stop+1:]...)
			retList = append(tokens[:start], tail...)
			if len(tokens) <= len(retList) {
				log.Panicf("Programmer error: why did it not join? len(tokens)==%d should be > len(retList)==%d", len(tokens), len(retList))
			}
			foundKey = false
			start = 0
			stop = 0
			// rewind one step back
			if i > 0 {
				i--
			}
		} else {
			i++
			if i >= len(tokens) {
				done = true
			}
		}
	}
	if len(retList) == 0 {
		retList = tokens
	}
	if (logLevel > 1) && foundKey {
		log.Printf("joinDelimited(Key:'%s')\n\tRequest:%+v(%2d)\n\t Joined:%+v(%2d)",
			key, tokens, len(tokens), retList, len(retList))
	}
	return retList
}

func splitAndAppend(s string, find string, tokens []string, tIndex int) []string {
	var tokenizedList []string
	if strings.Contains(s, find) {
		// found one, so do some insertion
		split := splitWithKeyInPlace(s, find)

		// replace new collection of lines with current line
		// i.e. "foo;bar" (len=1) -> "foo" ";" "bar" (len=3)
		// first, append the rest of the lines to new set of line
		var tail []string
		if (tIndex + 1) > len(tokens) {
			// nothing trailing, just make this the tail
			tail = split
		} else {
			// append next line ... to end
			tail = append(split, tokens[tIndex+1:]...)
		}
		// now cut current line, and append it
		tokenizedList = append(tokens[:tIndex], tail...)
	} else {
		// return unaltered list
		tokenizedList = tokens
	}

	return tokenizedList
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
			if strings.HasSuffix(qStr, "\";") {
				// split the closing quote + semicolon into two tokens
				retStrList = append(retStrList, qStr[:len(qStr)-1])
				retStrList = append(retStrList, ";")

			} else {
				retStrList = append(retStrList, qStr)
			}
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
				retStrList = splitAndRejoin(token, "{", retStrList, i)

				// try again: because next line has been joined to current, dec index
				i--
				continue
			}
			if strings.Contains(token, "}") {
				retStrList = splitAndRejoin(token, "}", retStrList, i)

				// try again: because next line has been joined to current, dec index
				i--
				continue
			}
			if strings.Contains(token, ";") {
				retStrList = splitAndRejoin(token, ";", retStrList, i)

				// try again: because next line has been joined to current, dec index
				i--
				continue
			}
		}

		// Now, make sure expressions such as 'a, b ,c - d, e,f' are treated as single expression 'a,b,c-d,e,f'
		retStrList = joinDelimited(retStrList, ":") // i.e. for vmap '{ 22:accept, 80 : drop, https:accept}'
		retStrList = joinDelimited(retStrList, "-")
		retStrList = joinDelimited(retStrList, ",") // do "," last so all types of lists are first combined
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
	//if strings.HasSuffix(retString, ";") {
	//	retString = retString[:len(retString)-1] + " ;"
	//}
	return retString, retCount
}

// breaks apart lines with ';' into two lines, and also takes into account quoted
// strings (in case the semi-colon is inside the quotes, which should not be split)
// At the same time, it will return multi-dimension to separte into blocks encountered
// by each encounter of '}' (it does not take account of whether the matching '{' were
// there)
type depthedStatement struct {
	tokens []string
	depth  uint16
}

func tokenizeMultiStatements(bodyOfText string) []depthedStatement {
	//log.Printf("Parsing:\n%s", bodyOfText)

	tokenizedLines := make([]depthedStatement, 0)

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
	for lineNum := 0; lineNum < len(lines); lineNum++ {
		line := lines[lineNum]
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
		// split tokens that are not whitespaced (i.e. 'ct state {established,new} accept;'
		// needs to split the '{', '}', and ';' into its own tokens
		tokens = splitNonWhitespaced(tokens)

		//log.Print(tokens)
		if len(tokens) > 0 {
			at := make([]string, 0)
			for ti, t := range tokens {
				if t == "" {
					continue
				}
				at = append(at, t)

				// treat each encounter of ";" as newline
				if (t == ";") || (t == "{") {
					// new statement
					if (len(at) > 0) && (at[0][0] != 0) {
						t := depthedStatement{tokens: at}
						tokenizedLines = append(tokenizedLines, t)
						at = make([]string, 0)
					}
				}

				// handle nested blocks which must associate to same expression,
				// for example 'ct state { established, new, accepted } accept'
				// needs to have the verdict 'accept' be associted to conntrack
				// state expression
				if t == "}" {
					// new line _ONLY_ if no tokens follow, else we need it on same line
					if ((ti + 1) >= len(tokens)) && (len(at) > 0) && (at[0][0] != 0) {
						t := depthedStatement{tokens: at}
						tokenizedLines = append(tokenizedLines, t)
						at = make([]string, 0)
					}
				}
			}
			if (len(at) > 0) && (at[0][0] != 0) {
				t := depthedStatement{tokens: at}
				tokenizedLines = append(tokenizedLines, t)
				at = make([]string, 0)
			}
		}
	}

	// Now that escaped lines have been joined back, we need to next split any line which
	// contains ';' into another line
	// Also, if there are any tokens after the '}', it needs to go under the same parent
	// For example, 'ct state { established, accepted} accept', which the verdict 'accept'
	// belongs to conntrack (ct) state
	currentDepth := 0
	for lineNum := 0; lineNum < len(tokenizedLines); lineNum++ {
		tokens := tokenizedLines[lineNum].tokens
		if tokenizedLines[lineNum].depth == 0 {
			// only set the depth if not yet set (see '}' logic of why)
			tokenizedLines[lineNum].depth = uint16(currentDepth)
		}

		lineStatement := fmt.Sprintf("#%3d:%2d:%s", lineNum, tokenizedLines[lineNum].depth, tabs[:tokenizedLines[lineNum].depth])
		for iToken := 0; iToken < len(tokens); iToken++ {
			token := tokens[iToken]
			if token == "{" {
				currentDepth++
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
			}
			if token == "}" {
				currentDepth--
				if currentDepth < 0 {
					log.Panicf("Encountered mismatched number of '{' for each '}' block")
				}

				// do not reduce indentation if there are any expression that follows '}', and also split them up
				if (iToken + 1) < len(tokens) {
					// split trailing tokens, but into same depth
					tailTokens := tokens[iToken+1:]
					tokens = tokens[:iToken+1] // include current token '}'
					tokenizedLines[lineNum].tokens = tokens

					// preset the depth so that it'll be in same depth/indentations
					tail := []depthedStatement{
						depthedStatement{depth: uint16(currentDepth + 1), tokens: tailTokens},
					}
					tail = append(tail, tokenizedLines[lineNum+1:]...)
					tokenizedLines = append(tokenizedLines[:lineNum+1], tail...) // include current line (that has been stripped)

					lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "' - split @ Line=" + strconv.Itoa(lineNum) + ", Depth=" + strconv.Itoa(int(tokenizedLines[lineNum+1].depth)) + ")"
					break // opt out of inner loop so we can start on next line of what we've appended
				}
			}
			if token == "" {
				continue
			}
			if token == ";" {
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
				continue
			}
			if strings.HasPrefix(token, "\"") || strings.HasPrefix(token, "'") {
				// skip any token that is quoted text
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
				continue
			}
			//if strings.Contains(token, ";") {
			//	lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
			//	// found one, so do some insertion
			//	tokenizedLines[lineNum].tokens = splitAndAppend(token, ";", tokens, iToken)
			//	token = tokens[iToken]
			//}
			lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
		} // for tokens
		//log.Print(lineStatement)
	} // for tokenizedLines
	if currentDepth != 0 {
		log.Panicf("Missing closing '}', current depth=%d", currentDepth)
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
func MakeStatements(textBody string) []*TTextStatement {
	// tokenizeMultiStatements basically returns blocks of []string
	tokenizedLines := tokenizeMultiStatements(textBody) // safety: this method won't split quoted text with semi-colons

	// NOTE: If anybody knows a better way to do this without pointer, you're welcome to fix this
	//       it's just easier to do link-list using pointer so it's the way I did it...
	var retStatements []*TTextStatement
	var iLine uint16 = 0
	for ; iLine < uint16(len(tokenizedLines)); iLine++ {
		if (len(tokenizedLines[iLine].tokens) >= 1) && (tokenizedLines[iLine].tokens[0] != "") {
			// line number returned will only be based on new major block, i.e. if a block has two tables:
			//	table ip filter{...}
			//	table ip6 filter{...}
			// it will only return from recursions at root, so it's safe to create new blocks each time here
			//log.Printf("\n=== Block at line %3d (depth: %d) TokenCount:%d-[%+v]", iLine, tokenizedLines[iLine].depth, len(tokenizedLines[iLine].tokens), tokenizedLines[iLine])
			pParent := new(TTextStatement) // pParent.Parent is ALWAYS nil
			retStatements = append(retStatements, pParent)

			// recurse into the statements for this block and honor the new line number it returns back
			iLine, _ = makeStatementRecursive(tokenizedLines, iLine, 0, pParent) // honor the line number it returns back to skip where needed (i.e. when '}' is encountered, it walked inside recursively)
			iLine--                                                              // because makeStatementRecursive() places to NEXT line, and the for{} loop incs, need to dec here
		}
	}
	return retStatements
}

func appendNewBlockStatement(pParent *TTextStatement, nextLineIndexRO uint16, linesRO []depthedStatement) *TTextStatement {
	if pParent == nil {
		log.Panicf("Parent pointer must not be nil")
	}
	if nextLineIndexRO == 0 {
		log.Panicf("In order for next index to be 0, current would mean it was -1, which is an invalid line number")
	}

	if int(nextLineIndexRO) >= len(linesRO) {
		// there are no child to be created if it is the last line
		return nil
	}
	//parentDepth := pParent.Depth
	//prevDepth := linesRO[nextLineIndexRO-1].depth
	nextDepth := linesRO[nextLineIndexRO].depth
	newChild := new(TTextStatement)
	newChild.Depth = nextDepth
	newChild.Parent = pParent
	pParent.SubStatement = append(pParent.SubStatement, newChild)

	//log.Printf("#Line: %2d - Parent.Depth=%d, previous Depth=%d, next Depth=%d - %+v", nextLineIndexRO, parentDepth, prevDepth, nextDepth, linesRO[nextLineIndexRO])
	return newChild
}

func makeStatementRecursive(linesRO []depthedStatement, lineIndexRO uint16, tokenIndexRO uint16, pCurrentBlockRO *TTextStatement) (uint16, uint16) {
	if pCurrentBlockRO == nil {
		log.Panicf("Programmer error: p should never be nil! - lineIndex=%d, tokenIndex=%d", lineIndexRO, tokenIndexRO)
	}
	if lineIndexRO >= uint16(len(linesRO)) {
		log.Panicf("L%2d:T%2d(S:%2d) Line Index >= %d", lineIndexRO, tokenIndexRO, len(pCurrentBlockRO.SubStatement), len(linesRO))
		return lineIndexRO, tokenIndexRO
	}
	if tokenIndexRO >= uint16(len(linesRO[lineIndexRO].tokens)) {
		log.Panicf("L%2d:T%2d(S:%2d) Token Index >= %d", lineIndexRO, tokenIndexRO, len(pCurrentBlockRO.SubStatement), len(linesRO[lineIndexRO].tokens))
		return lineIndexRO, tokenIndexRO
	}

	// TODO: Clean up this in future, no need to copy, all params are ref-copied anyways
	iLineIndex := lineIndexRO
	iTokenIndex := tokenIndexRO
	pCurrentBlock := pCurrentBlockRO

	// walk through statements based on depth
	for {
		logMsg := fmt.Sprintf("#L(%3d):T(%2d)[%12p](P:%12p) D(%2d)#%s", iLineIndex, len(linesRO[iLineIndex].tokens), pCurrentBlock, pCurrentBlock.Parent, linesRO[iLineIndex].depth, tabs[:linesRO[iLineIndex].depth])

		// walk through the tokens
		for ; (iTokenIndex < uint16(len(linesRO[iLineIndex].tokens))) && (int(iLineIndex) < len(linesRO)); iTokenIndex++ {
			// whether the token is '{', '}', or ';', record the token before we proceed
			token := linesRO[iLineIndex].tokens[iTokenIndex]
			pCurrentBlock.Tokens = append(pCurrentBlock.Tokens, token)

			logMsg += fmt.Sprintf("[%d]%s ", iTokenIndex, token)

			switch token {
			case "{":
				{
					// prepare for next token
					iTokenIndex++ // next token
					if iTokenIndex >= uint16(len(linesRO[iLineIndex].tokens)) {
						// move to next statement line
						iLineIndex++
						iTokenIndex = 0
					}
					if logLevel > 0 {
						log.Print(logMsg)
					}
					logMsg = ""

					// push: current block is the parent
					newChildBlock := appendNewBlockStatement(pCurrentBlock, iLineIndex, linesRO) // current block will be its parent
					iLineIndex, iTokenIndex = makeStatementRecursive(linesRO, iLineIndex, iTokenIndex, newChildBlock)
					continue // see what we have as next token (or wheter to move to next line)
				}

			case "}":
				{
					// pop (return to caller of matching "{" with current LineIndex and TokenIndex)
					// let the calling method continue on from where it took off (next token and line)
					if logLevel > 0 {
						log.Print(logMsg)
					}
					logMsg = ""
					return iLineIndex, iTokenIndex
				}

			case ";":
				{
					// only create next block if some token follows the ';'
					if int(iTokenIndex+1) < len(linesRO[iLineIndex].tokens) {
						// for token ";" it is same parent (append it to Parent), just new statement/line
						pCurrentBlock = appendNewBlockStatement(pCurrentBlock.Parent, iLineIndex+1, linesRO)
					}
				}
			} // switch toke
		} // for iTokenIndex
		if (logLevel > 0) && (logMsg != "") {
			log.Print(logMsg)
		}

		// next line
		iLineIndex++
		iTokenIndex = 0
		var d uint16 = 0
		if iLineIndex < uint16(len(linesRO)) {
			d = linesRO[iLineIndex].depth
		}
		//log.Printf("Next: Line=%d (out of %d), Depth=%d", iLineIndex, len(linesRO), d)
		// if next block is of depth 0, we're done - see if next/new statement belongs to this block
		if (iLineIndex >= uint16(len(linesRO))) || (d <= 0) {
			break
		}

		// Create new SubStatement and append it to the parent before we begin working with it
		pCurrentBlock = appendNewBlockStatement(pCurrentBlock.Parent, iLineIndex, linesRO)
		if pCurrentBlock == nil {
			// nothing in next line, we're done...
			break
		}
	} // for depth

	// if here, we're done with all tokens, so we can proceed to next line
	return iLineIndex, iTokenIndex
}
