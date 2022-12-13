module github.com/anuraaga/re2-go

go 1.18

require (
	github.com/anuraaga/re2-go/cre2 v0.0.0-20221202054428-a53fc718115e
	github.com/magefile/mage v1.14.0
	github.com/tetratelabs/wazero v1.0.0-pre.4.0.20221213074253-2e13f57f56a1
)

replace github.com/anuraaga/re2-go/cre2 => ./cre2
