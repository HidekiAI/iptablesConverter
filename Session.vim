let SessionLoad = 1
if &cp | set nocp | endif
nmap \ihn :IHN
nmap \is :IHS:A
nmap \ih :IHS
let s:cpo_save=&cpo
set cpo&vim
nmap gx <Plug>NetrwBrowseX
nnoremap <silent> <Plug>(go-alternate-split) :call go#alternate#Switch(0, "split")
nnoremap <silent> <Plug>(go-alternate-vertical) :call go#alternate#Switch(0, "vsplit")
nnoremap <silent> <Plug>(go-alternate-edit) :call go#alternate#Switch(0, "edit")
nnoremap <silent> <Plug>(go-vet) :call go#lint#Vet(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-lint) :call go#lint#Golint()
nnoremap <silent> <Plug>(go-metalinter) :call go#lint#Gometa(0)
nnoremap <silent> <Plug>(go-doc-browser) :call go#doc#OpenBrowser()
nnoremap <silent> <Plug>(go-doc-split) :call go#doc#Open("new", "split")
nnoremap <silent> <Plug>(go-doc-vertical) :call go#doc#Open("vnew", "vsplit")
nnoremap <silent> <Plug>(go-doc-tab) :call go#doc#Open("tabnew", "tabe")
nnoremap <silent> <Plug>(go-doc) :call go#doc#Open("new", "split")
nnoremap <silent> <Plug>(go-def-stack-clear) :call go#def#StackClear()
nnoremap <silent> <Plug>(go-def-stack) :call go#def#Stack()
nnoremap <silent> <Plug>(go-def-pop) :call go#def#StackPop()
nnoremap <silent> <Plug>(go-def-tab) :call go#def#Jump("tab")
nnoremap <silent> <Plug>(go-def-split) :call go#def#Jump("split")
nnoremap <silent> <Plug>(go-def-vertical) :call go#def#Jump("vsplit")
nnoremap <silent> <Plug>(go-def) :call go#def#Jump('')
nnoremap <silent> <Plug>(go-rename) :call go#rename#Rename(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-sameids-toggle) :call go#guru#ToggleSameIds()
nnoremap <silent> <Plug>(go-whicherrs) :call go#guru#Whicherrs(-1)
nnoremap <silent> <Plug>(go-sameids) :call go#guru#SameIds()
nnoremap <silent> <Plug>(go-referrers) :call go#guru#Referrers(-1)
nnoremap <silent> <Plug>(go-channelpeers) :call go#guru#ChannelPeers(-1)
xnoremap <silent> <Plug>(go-freevars) :call go#guru#Freevars(0)
nnoremap <silent> <Plug>(go-callstack) :call go#guru#Callstack(-1)
nnoremap <silent> <Plug>(go-describe) :call go#guru#Describe(-1)
nnoremap <silent> <Plug>(go-callers) :call go#guru#Callers(-1)
nnoremap <silent> <Plug>(go-callees) :call go#guru#Callees(-1)
nnoremap <silent> <Plug>(go-implements) :call go#guru#Implements(-1)
nnoremap <silent> <Plug>(go-imports) :call go#fmt#Format(1)
nnoremap <silent> <Plug>(go-import) :call go#import#SwitchImport(1, '', expand('<cword>'), '')
nnoremap <silent> <Plug>(go-info) :call go#tool#Info(0)
nnoremap <silent> <Plug>(go-deps) :call go#tool#Deps()
nnoremap <silent> <Plug>(go-files) :call go#tool#Files()
nnoremap <silent> <Plug>(go-coverage-browser) :call go#coverage#Browser(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-coverage-toggle) :call go#coverage#BufferToggle(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-coverage-clear) :call go#coverage#Clear()
nnoremap <silent> <Plug>(go-coverage) :call go#coverage#Buffer(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-test-compile) :call go#cmd#Test(!g:go_jump_to_error, 1)
nnoremap <silent> <Plug>(go-test-func) :call go#cmd#TestFunc(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-test) :call go#cmd#Test(!g:go_jump_to_error, 0)
nnoremap <silent> <Plug>(go-install) :call go#cmd#Install(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-generate) :call go#cmd#Generate(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-build) :call go#cmd#Build(!g:go_jump_to_error)
nnoremap <silent> <Plug>(go-run) :call go#cmd#Run(!g:go_jump_to_error)
nnoremap <silent> <Plug>NetrwBrowseX :call netrw#NetrwBrowseX(expand("<cfile>"),0)
nnoremap <SNR>20_: :=v:count ? v:count : ''
imap \ihn :IHN
imap \is :IHS:A
imap \ih :IHS
let &cpo=s:cpo_save
unlet s:cpo_save
set autowrite
set background=dark
set backspace=indent,eol,start
set balloonexpr=SyntasticBalloonsExprNotifier()
set completeopt=longest,menuone
set errorformat=%-G#\ %.%#,%-G%.%#panic:\ %m,%Ecan't\ load\ package:\ %m,%A%f:%l:%c:\ %m,%A%f:%l:\ %m,%C%*\\s%m,%-G%.%#
set fileencodings=ucs-bom,utf-8,default,latin1
set formatoptions=q
set helplang=en
set hidden
set hlsearch
set ignorecase
set incsearch
set listchars=tab:→ˑ,trail:·,eol:¶,nbsp:ˆ,extends:»,precedes:«
set nomodeline
set mouse=a
set omnifunc=syntaxcomplete#Complete
set printoptions=paper:letter
set ruler
set runtimepath=~/.vim,~/.vim/bundle/omnisharp-vim,~/.vim/bundle/syntastic,~/.vim/bundle/vim-go,~/.vim/plugged/vim-fugitive/,/var/lib/vim/addons,/usr/share/vim/vimfiles,/usr/share/vim/vim74,/usr/share/vim/vimfiles/after,/var/lib/vim/addons/after,~/.vim/after
set showcmd
set showmatch
set smartcase
set suffixes=.bak,~,.swp,.o,.info,.aux,.log,.dvi,.bbl,.blg,.brf,.cb,.ind,.idx,.ilg,.inx,.out,.toc
set tabstop=4
set tags=./tags,tags,./src/tags;/home/hidekiai
let s:so_save = &so | let s:siso_save = &siso | set so=0 siso=0
let v:this_session=expand("<sfile>:p")
silent only
cd ~/projects/iptablesConverter
if expand('%') == '' && !&modified && line('$') <= 1 && getline(1) == ''
  let s:wipebuf = bufnr('%')
endif
set shortmess=aoO
badd +38 src/iptablesConverter/nftables/authHeader.go
badd +19 src/iptablesConverter/nftables/ethernet.go
badd +155 src/iptablesConverter/nftables/connTrack.go
badd +45 src/iptablesConverter/nftables/streamControlTransmissionProtocol.go
badd +635 src/iptablesConverter/nftables/nftables.go
badd +33 src/iptablesConverter/nftables/counter.go
badd +31 src/iptablesConverter/nftables/arp.go
badd +113 src/iptablesConverter/nftables/log.go
badd +50 src/iptablesConverter/nftables/queue.go
badd +36 src/iptablesConverter/nftables/datagramCongestionControlProtocol.go
badd +23 src/iptablesConverter/nftables/destination.go
badd +31 src/iptablesConverter/nftables/routing.go
badd +220 src/iptablesConverter/nftables/meta.go
badd +41 src/iptablesConverter/nftables/icmp.go
badd +1 src/iptablesConverter/nftables/nftables_test.go
badd +63 src/iptablesConverter/nftables/nat.go
badd +108 src/iptablesConverter/nftables/ip6.go
badd +73 src/iptablesConverter/nftables/icmpv6.go
badd +45 src/iptablesConverter/nftables/udp.go
badd +83 src/iptablesConverter/nftables/tcp.go
badd +23 src/iptablesConverter/nftables/hopByHop.go
badd +642 src/iptablesConverter/nftables/nftablesImplementations.go
badd +30 src/iptablesConverter/nftables/vlan.go
badd +43 src/iptablesConverter/nftables/limit.go
badd +33 src/iptablesConverter/nftables/fragment.go
badd +66 src/iptablesConverter/nftables/reject.go
badd +95 src/iptablesConverter/nftables/ip.go
badd +35 src/iptablesConverter/nftables/mobilityHeader.go
badd +41 src/iptablesConverter/nftables/verdict.go
badd +26 src/iptablesConverter/nftables/encapsulatingSecurityPayload.go
badd +34 src/iptablesConverter/nftables/parser.go
badd +33 src/iptablesConverter/nftables/ipCompression.go
badd +40 src/iptablesConverter/nftables/udpLite.go
badd +58 Makefile
argglobal
silent! argdel *
argadd src/iptablesConverter/nftables/authHeader.go
argadd src/iptablesConverter/nftables/ethernet.go
argadd src/iptablesConverter/nftables/connTrack.go
argadd src/iptablesConverter/nftables/streamControlTransmissionProtocol.go
argadd src/iptablesConverter/nftables/nftables.go
argadd src/iptablesConverter/nftables/counter.go
argadd src/iptablesConverter/nftables/arp.go
argadd src/iptablesConverter/nftables/log.go
argadd src/iptablesConverter/nftables/queue.go
argadd src/iptablesConverter/nftables/datagramCongestionControlProtocol.go
argadd src/iptablesConverter/nftables/destination.go
argadd src/iptablesConverter/nftables/routing.go
argadd src/iptablesConverter/nftables/meta.go
argadd src/iptablesConverter/nftables/icmp.go
argadd src/iptablesConverter/nftables/nftables_test.go
argadd src/iptablesConverter/nftables/nat.go
argadd src/iptablesConverter/nftables/ip6.go
argadd src/iptablesConverter/nftables/icmpv6.go
argadd src/iptablesConverter/nftables/udp.go
argadd src/iptablesConverter/nftables/tcp.go
argadd src/iptablesConverter/nftables/hopByHop.go
argadd src/iptablesConverter/nftables/nftablesImplementations.go
argadd src/iptablesConverter/nftables/vlan.go
argadd src/iptablesConverter/nftables/limit.go
argadd src/iptablesConverter/nftables/fragment.go
argadd src/iptablesConverter/nftables/reject.go
argadd src/iptablesConverter/nftables/ip.go
argadd src/iptablesConverter/nftables/mobilityHeader.go
argadd src/iptablesConverter/nftables/verdict.go
argadd src/iptablesConverter/nftables/encapsulatingSecurityPayload.go
argadd src/iptablesConverter/nftables/parser.go
argadd src/iptablesConverter/nftables/ipCompression.go
argadd src/iptablesConverter/nftables/udpLite.go
edit src/iptablesConverter/nftables/meta.go
set splitbelow splitright
wincmd _ | wincmd |
vsplit
1wincmd h
wincmd w
set nosplitbelow
set nosplitright
wincmd t
set winheight=1 winwidth=1
exe 'vert 1resize ' . ((&columns * 160 + 120) / 240)
exe 'vert 2resize ' . ((&columns * 79 + 120) / 240)
argglobal
edit src/iptablesConverter/nftables/meta.go
nnoremap <buffer> <silent>  :call go#def#StackPop(v:count1)
nnoremap <buffer> <silent> ] :call go#def#Jump("split")
nnoremap <buffer> <silent>  :call go#def#Jump("split")
nnoremap <buffer> <silent>  :GoDef
nnoremap <buffer> <silent> K :GoDoc
xnoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('v', 'prev')
onoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('o', 'prev')
nnoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('n', 'prev')
xnoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('v', 'next')
onoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('o', 'next')
nnoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('n', 'next')
xnoremap <buffer> <silent> af :call go#textobj#Function('a')
onoremap <buffer> <silent> af :call go#textobj#Function('a')
nnoremap <buffer> <silent> gd :GoDef
xnoremap <buffer> <silent> if :call go#textobj#Function('i')
onoremap <buffer> <silent> if :call go#textobj#Function('i')
setlocal keymap=
setlocal noarabic
setlocal autoindent
setlocal backupcopy=
setlocal balloonexpr=
setlocal nobinary
setlocal nobreakindent
setlocal breakindentopt=
setlocal bufhidden=
setlocal buflisted
setlocal buftype=
setlocal nocindent
setlocal cinkeys=0{,0},0),:,0#,!^F,o,O,e
setlocal cinoptions=
setlocal cinwords=if,else,while,do,for,switch
setlocal colorcolumn=
setlocal comments=s1:/*,mb:*,ex:*/,://
setlocal commentstring=//\ %s
setlocal complete=.,w,b,u,t,i
setlocal concealcursor=
setlocal conceallevel=0
setlocal completefunc=
setlocal nocopyindent
setlocal cryptmethod=
setlocal nocursorbind
setlocal nocursorcolumn
setlocal nocursorline
setlocal define=
setlocal dictionary=
setlocal nodiff
setlocal equalprg=
setlocal errorformat=%-G#\ %.%#,%-G%.%#panic:\ %m,%Ecan't\ load\ package:\ %m,%A%f:%l:%c:\ %m,%A%f:%l:\ %m,%C%*\\s%m,%-G%.%#
setlocal noexpandtab
if &filetype != 'go'
setlocal filetype=go
endif
setlocal foldcolumn=0
setlocal foldenable
setlocal foldexpr=0
setlocal foldignore=#
setlocal foldlevel=0
setlocal foldmarker={{{,}}}
setlocal foldmethod=manual
setlocal foldminlines=1
setlocal foldnestmax=20
setlocal foldtext=foldtext()
setlocal formatexpr=
setlocal formatoptions=q
setlocal formatlistpat=^\\s*\\d\\+[\\]:.)}\\t\ ]\\s*
setlocal grepprg=
setlocal iminsert=2
setlocal imsearch=2
setlocal include=
setlocal includeexpr=
setlocal indentexpr=GoIndent(v:lnum)
setlocal indentkeys=0{,0},:,0#,!^F,o,O,e,<:>,0=},0=)
setlocal noinfercase
setlocal iskeyword=@,48-57,_,192-255
setlocal keywordprg=
setlocal nolinebreak
setlocal nolisp
setlocal lispwords=
setlocal nolist
setlocal makeprg=make
setlocal matchpairs=(:),{:},[:]
setlocal nomodeline
setlocal modifiable
setlocal nrformats=octal,hex
set number
setlocal number
setlocal numberwidth=4
setlocal omnifunc=go#complete#Complete
setlocal path=
setlocal nopreserveindent
setlocal nopreviewwindow
setlocal quoteescape=\\
setlocal noreadonly
setlocal norelativenumber
setlocal norightleft
setlocal rightleftcmd=search
setlocal noscrollbind
setlocal shiftwidth=8
setlocal noshortname
setlocal nosmartindent
setlocal softtabstop=0
setlocal nospell
setlocal spellcapcheck=[.?!]\\_[\\])'\"\	\ ]\\+
setlocal spellfile=
setlocal spelllang=en
setlocal statusline=
setlocal suffixesadd=
setlocal swapfile
setlocal synmaxcol=3000
if &syntax != 'go'
setlocal syntax=go
endif
setlocal tabstop=4
setlocal tags=
setlocal textwidth=0
setlocal thesaurus=
setlocal noundofile
setlocal undolevels=-123456
setlocal nowinfixheight
setlocal nowinfixwidth
set nowrap
setlocal nowrap
setlocal wrapmargin=0
silent! normal! zE
let s:l = 760 - ((46 * winheight(0) + 32) / 64)
if s:l < 1 | let s:l = 1 | endif
exe s:l
normal! zt
760
normal! 012|
lcd ~/projects/iptablesConverter
wincmd w
argglobal
edit ~/projects/iptablesConverter/src/iptablesConverter/nftables/nftables.go
nnoremap <buffer> <silent>  :call go#def#StackPop(v:count1)
nnoremap <buffer> <silent> ] :call go#def#Jump("split")
nnoremap <buffer> <silent>  :call go#def#Jump("split")
nnoremap <buffer> <silent>  :GoDef
nnoremap <buffer> <silent> K :GoDoc
xnoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('v', 'prev')
onoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('o', 'prev')
nnoremap <buffer> <silent> [[ :call go#textobj#FunctionJump('n', 'prev')
xnoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('v', 'next')
onoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('o', 'next')
nnoremap <buffer> <silent> ]] :call go#textobj#FunctionJump('n', 'next')
xnoremap <buffer> <silent> af :call go#textobj#Function('a')
onoremap <buffer> <silent> af :call go#textobj#Function('a')
nnoremap <buffer> <silent> gd :GoDef
xnoremap <buffer> <silent> if :call go#textobj#Function('i')
onoremap <buffer> <silent> if :call go#textobj#Function('i')
setlocal keymap=
setlocal noarabic
setlocal autoindent
setlocal backupcopy=
setlocal balloonexpr=
setlocal nobinary
setlocal nobreakindent
setlocal breakindentopt=
setlocal bufhidden=
setlocal buflisted
setlocal buftype=
setlocal nocindent
setlocal cinkeys=0{,0},0),:,0#,!^F,o,O,e
setlocal cinoptions=
setlocal cinwords=if,else,while,do,for,switch
setlocal colorcolumn=
setlocal comments=s1:/*,mb:*,ex:*/,://
setlocal commentstring=//\ %s
setlocal complete=.,w,b,u,t,i
setlocal concealcursor=
setlocal conceallevel=0
setlocal completefunc=
setlocal nocopyindent
setlocal cryptmethod=
setlocal nocursorbind
setlocal nocursorcolumn
setlocal nocursorline
setlocal define=
setlocal dictionary=
setlocal nodiff
setlocal equalprg=
setlocal errorformat=%-G#\ %.%#,%-G%.%#panic:\ %m,%Ecan't\ load\ package:\ %m,%A%f:%l:%c:\ %m,%A%f:%l:\ %m,%C%*\\s%m,%-G%.%#
setlocal noexpandtab
if &filetype != 'go'
setlocal filetype=go
endif
setlocal foldcolumn=0
setlocal foldenable
setlocal foldexpr=0
setlocal foldignore=#
setlocal foldlevel=0
setlocal foldmarker={{{,}}}
setlocal foldmethod=manual
setlocal foldminlines=1
setlocal foldnestmax=20
setlocal foldtext=foldtext()
setlocal formatexpr=
setlocal formatoptions=q
setlocal formatlistpat=^\\s*\\d\\+[\\]:.)}\\t\ ]\\s*
setlocal grepprg=
setlocal iminsert=2
setlocal imsearch=2
setlocal include=
setlocal includeexpr=
setlocal indentexpr=GoIndent(v:lnum)
setlocal indentkeys=0{,0},:,0#,!^F,o,O,e,<:>,0=},0=)
setlocal noinfercase
setlocal iskeyword=@,48-57,_,192-255
setlocal keywordprg=
setlocal nolinebreak
setlocal nolisp
setlocal lispwords=
setlocal nolist
setlocal makeprg=make
setlocal matchpairs=(:),{:},[:]
setlocal nomodeline
setlocal modifiable
setlocal nrformats=octal,hex
set number
setlocal number
setlocal numberwidth=4
setlocal omnifunc=go#complete#Complete
setlocal path=
setlocal nopreserveindent
setlocal nopreviewwindow
setlocal quoteescape=\\
setlocal noreadonly
setlocal norelativenumber
setlocal norightleft
setlocal rightleftcmd=search
setlocal noscrollbind
setlocal shiftwidth=8
setlocal noshortname
setlocal nosmartindent
setlocal softtabstop=0
setlocal nospell
setlocal spellcapcheck=[.?!]\\_[\\])'\"\	\ ]\\+
setlocal spellfile=
setlocal spelllang=en
setlocal statusline=
setlocal suffixesadd=
setlocal swapfile
setlocal synmaxcol=3000
if &syntax != 'go'
setlocal syntax=go
endif
setlocal tabstop=4
setlocal tags=
setlocal textwidth=0
setlocal thesaurus=
setlocal noundofile
setlocal undolevels=-123456
setlocal nowinfixheight
setlocal nowinfixwidth
set nowrap
setlocal nowrap
setlocal wrapmargin=0
silent! normal! zE
let s:l = 421 - ((49 * winheight(0) + 32) / 64)
if s:l < 1 | let s:l = 1 | endif
exe s:l
normal! zt
421
normal! 0
lcd ~/projects/iptablesConverter
wincmd w
exe 'vert 1resize ' . ((&columns * 160 + 120) / 240)
exe 'vert 2resize ' . ((&columns * 79 + 120) / 240)
tabnext 1
if exists('s:wipebuf')
  silent exe 'bwipe ' . s:wipebuf
endif
unlet! s:wipebuf
set winheight=1 winwidth=20 shortmess=filnxtToO
let s:sx = expand("<sfile>:p:r")."x.vim"
if file_readable(s:sx)
  exe "source " . fnameescape(s:sx)
endif
let &so = s:so_save | let &siso = s:siso_save
doautoall SessionLoadPost
unlet SessionLoad
" vim: set ft=vim :
