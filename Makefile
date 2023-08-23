RSCRIPT = Rscript

test:
	${RSCRIPT} -e 'library(methods); devtools::test()'

roxygen:
	@mkdir -p man
	${RSCRIPT} -e "library(methods); devtools::document()"

install:
	R CMD INSTALL .

build:
	R CMD build .

check:
	_R_CHECK_CRAN_INCOMING_=FALSE make check_all

check_all:
	${RSCRIPT} -e "rcmdcheck::rcmdcheck(args = c('--as-cran', '--no-manual'))"

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

pkgdown:
	Rscript -e 'pkgdown::build_site()'

manual:
	R CMD Rd2pdf --no-clean .

clean:
	rm -rf .Rd2pdf*


.PHONY: test roxygen install build check check_all vignettes
