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
}

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
		// i.e. line such as 'Root{child1{child2' would become 'Root { child1 { child2'
		tempStr := strings.Replace(s, find, " "+find+" ", -1)
		// now split by space
		split = strings.Fields(tempStr)
	}
	return split
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
				split := splitWithKeyInPlace(token, "{")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)
				//log.Printf("Token='%s'\nsplit(%d):%+v\ntail(%d):%+v\nNewList(%d):%+v\n\n", token, len(split), split, len(tail), tail, len(retStrList), retStrList)

				// try again
				i--
				continue
			}
			if strings.Contains(token, "}") {
				split := splitWithKeyInPlace(token, "}")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)
				//log.Printf("Token='%s'\nsplit(%d):%+v\ntail(%d):%+v\nNewList(%d):%+v\n\n", token, len(split), split, len(tail), tail, len(retStrList), retStrList)

				// try again
				i--
				continue
			}
			if strings.Contains(token, ";") {
				split := splitWithKeyInPlace(token, ";")
				tail := append(split, retStrList[i+1:]...)
				retStrList = append(retStrList[:i], tail...)
				//log.Printf("Token='%s'\nsplit(%d):%+v\ntail(%d):%+v\nNewList(%d):%+v\n\n", token, len(split), split, len(tail), tail, len(retStrList), retStrList)

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
		if len(tokens) > 0 {
			at := make([]string, 0)
			for _, t := range tokens {
				at = append(at, t)
				// treat each encounter of ";" as newline
				if t == ";" || t == "}" || t == "{" {
					// new line
					t := depthedStatement{tokens: at}
					tokenizedLines = append(tokenizedLines, t)
					at = make([]string, 0)
				}
			}
			if len(at) > 0 {
				t := depthedStatement{tokens: at}
				tokenizedLines = append(tokenizedLines, t)
				at = make([]string, 0)
			}
		}
	}

	// Now that escaped lines have been joined back, we need to next split any line which
	// contains ';' into another line
	indent := "|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|"
	indentIndex := 0
	for lineNum := 0; lineNum < len(tokenizedLines); lineNum++ {
		tokens := tokenizedLines[lineNum].tokens
		tokenizedLines[lineNum].depth = uint16(indentIndex)

		lineStatement := fmt.Sprintf("#%3d:%2d:%s", lineNum, tokenizedLines[lineNum].depth, indent[:indentIndex])
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
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
				continue
			}
			if strings.HasPrefix(token, "\"") || strings.HasPrefix(token, "'") {
				// skip any token that is quoted text
				lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
				continue
			}
			if strings.Contains(token, ";") {
				// found one, so do some insertion
				tokenizedLines[lineNum].tokens = splitAndAppend(token, ";", tokens, iToken)
				token = tokens[iToken]
			}
			lineStatement += "(" + strconv.Itoa(iToken) + ",'" + token + "'), "
		}
		//log.Print(lineStatement)
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
		// line number returned will only be based on new major block, i.e. if a block has two tables:
		//	table ip filter{...}
		//	table ip6 filter{...}
		// it will only return from recursions at root, so it's safe to create new blocks each time here
		//log.Printf("\n=== Block at line %3d (depth: %d) [%+v]", iLine, tokenizedLines[iLine].depth, tokenizedLines[iLine])
		pParent := new(TTextStatement) // pParent.Parent is ALWAYS nil
		retStatements = append(retStatements, pParent)
		iLine, _ = makeStatementRecursive(tokenizedLines, iLine, 0, pParent) // honor the line number it returns back to skip where needed (i.e. when '}' is encountered, it walked inside recursively)
	}
	return retStatements
}

func appendNewBlockStatement(pParent *TTextStatement) *TTextStatement {
	newChild := new(TTextStatement)
	newChild.Parent = pParent
	pParent.SubStatement = append(pParent.SubStatement, newChild)
	return newChild
}

func makeStatementRecursive(linesRO []depthedStatement, lineIndexRO uint16, tokenIndexRO uint16, pParentRO *TTextStatement) (uint16, uint16) {
	if pParentRO == nil {
		log.Panicf("Programmer error: p should never be nil! - lineIndex=%d, tokenIndex=%d", lineIndexRO, tokenIndexRO)
	}
	if lineIndexRO >= uint16(len(linesRO)) {
		log.Panicf("L%2d:T%2d(S:%2d) Line Index >= %d",
			lineIndexRO,
			tokenIndexRO,
			len(pParentRO.SubStatement),
			len(linesRO))
		return lineIndexRO, tokenIndexRO
	}
	if tokenIndexRO >= uint16(len(linesRO[lineIndexRO].tokens)) {
		log.Panicf("L%2d:T%2d(S:%2d) Token Index >= %d",
			lineIndexRO,
			tokenIndexRO,
			len(pParentRO.SubStatement),
			len(linesRO[lineIndexRO].tokens))
		return lineIndexRO, tokenIndexRO
	}

	// TODO: Clean up this in future, no need to copy, all params are ref-copied anyways
	iLineIndex := lineIndexRO
	iTokenIndex := tokenIndexRO

	// walk through statements based on depth
	for {
		// Create new SubStatement and append it to the parent before we begin working with it
		pCurrentBlock := appendNewBlockStatement(pParentRO)

		logMsg := fmt.Sprintf("L%2d:T%2d[%12p](P:%12p,S:%2d) %2d %s",
			lineIndexRO,
			tokenIndexRO,
			pCurrentBlock,
			pParentRO,
			len(pParentRO.SubStatement),
			linesRO[lineIndexRO].depth,
			tabs[:linesRO[lineIndexRO].depth])

		//log.Printf("\n\n### L%2d:T%2d[%12p]>>> Processing '%+v'", lineIndexRO, tokenIndexRO, pCurrentBlock, linesRO[iLineIndex])
		//log.Printf("# %2d:%2d %s%+v", iLineIndex, linesRO[iLineIndex].depth, tabs[:linesRO[iLineIndex].depth], linesRO[iLineIndex])
		// walk through the tokens
		for ; iTokenIndex < uint16(len(linesRO[iLineIndex].tokens)); iTokenIndex++ {
			// whether the token is '{', '}', or ';', record the token before we proceed
			token := linesRO[iLineIndex].tokens[iTokenIndex]
			pCurrentBlock.Tokens = append(pCurrentBlock.Tokens, token)

			logMsg += "'" + token + "',"

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

					// push: current block is the parent
					//log.Printf("\t>>> Token='%s' - Preparing for next set '%+v'", token, linesRO[iLineIndex])
					iLineIndex, iTokenIndex = makeStatementRecursive(linesRO, iLineIndex, iTokenIndex, pCurrentBlock)

					// the "}" will return new LineIndex and TokenIndex - by the time '}' is encountered,
					// it may have proceeded several tokens (and lines) due to nested blocks
					continue // see what we have as next token
				}

			case "}":
				{
					//log.Printf("\t<<< Token='%s' DONE - returning iLine=%d, iToken=%d (Next: '%+v')\n\n", token, iLineIndex, iTokenIndex, linesRO[iLineIndex])
					// pop (return to caller of matching "{" with current LineIndex and TokenIndex)
					// let the calling method continue on from where it took off (next token)
					return iLineIndex, iTokenIndex
				}

			case ";":
				{
					// only create next block if some token follows the ';'
					if (iTokenIndex + 1) < uint16(len(linesRO[iLineIndex].tokens)) {
						// for token ";" it is same parent (append it to Parent), just new statement/line
						pCurrentBlock = appendNewBlockStatement(pParentRO)
					}
				}
			} // switch toke
		} // for iTokenIndex
		//log.Print(logMsg)

		// see if next/new statement belongs to this block
		if (iLineIndex+1 >= uint16(len(linesRO))) || (linesRO[iLineIndex+1].depth <= 0) {
			break
		}
		iLineIndex++
		iTokenIndex = 0
	} // for depth

	// if here, we're done with all tokens, so we can proceed to next line
	return iLineIndex, iTokenIndex
}
