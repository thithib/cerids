########################################################################################
# File    : Makefile                                                                   #
# Author  : Haidar-Bachminska Pierre-Antoine                                           #
# Mail    : hydraze (at symbol) hydraze (the perfect dot symbol) org                   #
# Licence : GNU/GPLv3 or later                                                         #
########################################################################################

#########################################################################################
#       This file is part of CerIDS                                                    #
#                                                                                      #
#       CerIDS is free software: you can redistribute it and/or modify                 #
#       it under the terms of the GNU General Public License as published by           #
#       the Free Software Foundation, either version 3 of the License, or              #
#       (at your option) any later version.                                            #
#                                                                                      #
#       CerIDS is distributed in the hope that it will be useful,                      #
#       but WITHOUT ANY WARRANTY; without even the implied warranty of                 #
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                  #
#       GNU General Public License for more details.                                   #
#                                                                                      #
#       You should have received a copy of the GNU General Public License              #
#       along with CerIDS.  If not, see <http://www.gnu.org/licenses/>.                #
#                                                                                      #
#########################################################################################

CC=gcc
LDFLAG=-lpcap
CFLAG=-std=gnu99
EXEC=cerids

all: $(EXEC) 

$(EXEC): main.o 
				@$(CC) -o $@ $^ $(LDFLAG)

%.o: %.c
				@$(CC) -o $@ -c $< $(CFLAG)


.PHONY: clean mrproper 

clean:
				@rm -f *.o

mrproper: clean
				@rm -f $(EXEC)
