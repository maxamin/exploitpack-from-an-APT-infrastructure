Install
=======

For full mapping support, download and uncompress the GeoIP City database 
into the CANVAS/gui/WorldMap/ directory. 

You can just place the uncompressed (GeoLiteCity.dat) City Database in 
CANVAS/gui/WorldMap. CANVAS expects the database to be named 'GeoLiteCity.dat'.

Notes for Linux users
=====================

wget -c http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
gunzip GeoLiteCity.dat.gz
#ubuntu
apt-get install python-geoip
#If running Fedora, there is a fedora.sh to help you through this process.

Downloads
=========

Current GeoLite CITY Database:

http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
Uncompress this on Windows with gzip for Windows or most other compression utilities.


Map Credit
==========

http://visibleearth.nasa.gov/view_rec.php?id=2433

Full Map Credit
===============

NASA Goddard Space Flight Center Image by Reto St�ckli (land 
surface, shallow water, clouds). Enhancements by Robert Simmon (ocean 
color, compositing, 3D globes, animation). Data and technical support: 
MODIS Land Group; MODIS Science Data Support Team; MODIS Atmosphere 
Group; MODIS Ocean Group Additional data: USGS EROS Data Center 
(topography); USGS Terrestrial Remote Sensing Flagstaff Field Center 
(Antarctica); Defense Meteorological Satellite Program (city lights).

http://visibleearth.nasa.gov/useterms.php

Map PNG Size
============

Our simple projection algo takes 2048 * 1024 sized maps. Using a 
standard longitude/latitude degree to coordinate projection algorithm.

