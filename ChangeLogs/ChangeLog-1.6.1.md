
Change Log for Release libpri-1.6.1
========================================

Links:
----------------------------------------

 - [Full ChangeLog](https://downloads.asterisk.org/pub/telephony/libpri/releases/ChangeLog-1.6.1.md)  
 - [GitHub Diff](https://github.com/asterisk/libpri/compare/1.6.0...1.6.1)  
 - [Tarball](https://downloads.asterisk.org/pub/telephony/libpri/libpri-1.6.1.tar.gz)  
 - [Downloads](https://downloads.asterisk.org/pub/telephony/libpri)  

Summary:
----------------------------------------

- .github: Add Releaser workflow
- Link README to README.md
- Makefile: Fix modern compiler errors.
- Makefile: Add the ability to build libpri on MacOS for Linux target.
- q931.c: Fix subaddress finding octet 4.

User Notes:
----------------------------------------


Upgrade Notes:
----------------------------------------


Closed Issues:
----------------------------------------

None

Commits By Author:
----------------------------------------

- ### George Joseph (2):
  - Link README to README.md
  - .github: Add Releaser workflow

- ### Sean Bright (1):
  - Makefile: Fix modern compiler errors.

- ### Sergey V. Lobanov (1):
  - Makefile: Add the ability to build libpri on MacOS for Linux target.

- ### bbabic (1):
  - q931.c: Fix subaddress finding octet 4.


Detail:
----------------------------------------

- ### .github: Add Releaser workflow
  Author: George Joseph  
  Date:   2023-08-16  


- ### Link README to README.md
  Author: George Joseph  
  Date:   2023-08-15  


- ### Makefile: Fix modern compiler errors.
  Author: Sean Bright  
  Date:   2023-03-10  

  Disable GCC's zero-length-bounds and stringop-overflow errors.

  PRI-189 #close


- ### Makefile: Add the ability to build libpri on MacOS for Linux target.
  Author: Sergey V. Lobanov  
  Date:   2022-02-19  

  This patch allows to redefine ar and ranlib tool using AR and
  RANLIB make flags.

  PRI-188 #close


- ### q931.c: Fix subaddress finding octet 4.
  Author: bbabic  
  Date:   2017-10-23  

  Some switches have extended subaddress ie octet 3 encoding to be
  multi-octet.

  * Update dump and receive helper functions to search for the end of octet
  3 encoding to determine where octet 4 starts.

  ASTERISK-27342


