#! /bin/sh

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
FILENAME="$(basename "$0")"
ROOT_PATH="$(dirname "$(realpath "$0")")"

if [ -d "$ROOT_PATH/.canvas_venv/" ]; then
	PYTHON="$ROOT_PATH/.canvas_venv/bin/python"
else
	PYTHON="/usr/bin/env python"
fi

$PYTHON "$ROOT_PATH/runcanvas.py" $*
