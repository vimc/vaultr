RSCRIPT = Rscript --no-init-file

test:
	VAULTR_TEST_SERVER_BIN_PATH=${PWD}/.vault ${RSCRIPT} -e 'library(methods); devtools::test()'

roxygen:
	@mkdir -p man
	${RSCRIPT} -e "library(methods); devtools::document()"

install:
	R CMD INSTALL .

install_vault:
	VAULTR_TEST_SERVER_INSTALL=true inst/server/install-server.R .vault

uninstall_vault:
	rm -rf .vault

build:
	R CMD build .

check:
	_R_CHECK_CRAN_INCOMING_=FALSE make check_all

check_all:
	VAULTR_TEST_SERVER_BIN_PATH=${PWD}/.vault ${RSCRIPT} -e "rcmdcheck::rcmdcheck(args = c('--as-cran', '--no-manual'))"

vignettes_src/%.Rmd: vignettes_src/%.R
	${RSCRIPT} -e 'library(sowsear); sowsear("$<", output="$@")'

vignettes/vaultr.Rmd: vignettes_src/vaultr.Rmd
	cd vignettes_src && Rscript -e 'knitr::knit("vaultr.Rmd")'
	mv vignettes_src/vaultr.md $@
	sed -i.bak 's/[[:space:]]*$$//' $@
	rm -f $@.bak

vignettes/packages.Rmd: vignettes_src/packages.Rmd
	cd vignettes_src && Rscript -e 'knitr::knit("packages.Rmd")'
	mv vignettes_src/packages.md $@
	sed -i.bak 's/[[:space:]]*$$//' $@
	rm -f $@.bak

vignettes_install: vignettes/vaultr.Rmd vignettes/packages.Rmd
	Rscript -e 'library(methods); devtools::build_vignettes()'

vignettes:
	make vignettes_install

README.md: README.Rmd
	Rscript -e "options(warnPartialMatchArgs=FALSE); knitr::knit('$<')"
	sed -i.bak 's/[[:space:]]*$$//' README.md
	rm -f $@.bak

.PHONY: test roxygen install build check check_all vignettes
