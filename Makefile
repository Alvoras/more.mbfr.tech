default: help

## help : Show this help
help: Makefile
	@printf "\nmore.hbouffier.info pages\n\n"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@printf ""

## deploy : Deploy website 
deploy:
	mkdocs gh-deploy

## serve : Serve website locally
serve:
	mkdocs serve

