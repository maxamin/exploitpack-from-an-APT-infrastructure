#!/bin/bash -e

# in case ran manually
set -e

# the use of "realpath" is to make sure file paths are clean
FILENAME="$(basename "$0")"
INSTALLER_PATH="$(dirname "$(realpath "$0")")"
INSTALLER_LOG="$INSTALLER_PATH/install.log"
ROOT_PATH="$(realpath "$INSTALLER_PATH/..")"
VENV_PATH="$ROOT_PATH/.canvas_venv"

# minimal system packages required
#SYSTEM_PACKAGES=(python python-virtualenv gtk2.0 build-essential git wget libglade2-dev python-dev libgirepository1.0-dev libcanberra-gtk3-module intltool libncurses5-dev automake)

SYSTEM_PACKAGES=(python python-virtualenv git wget intltool automake libtool python-pip)
APT_PACKAGES=(libjpeg-dev gtk2.0 itstool python-gtk2 build-essential python-dev libgirepository1.0-dev libcanberra-gtk3-module libncurses5-dev libgeoip-dev libxml2 libxml2-dev libssl-dev libffi-dev)
YUM_PACKAGES=(make gcc gcc-c++ kernel-devel libxml2 libxml2-devel gtk2 python-devel gobject-introspection gobject-introspection-devel geoip-devel libcanberra-gtk3 ncurses-libs ncurses-devel cairo-devel openssl-devel libffi-devel)

# minimal pip packages
PIP_PACKAGES=(diskcache==4.1.0 numpy pyopenssl pyzmq pyasn1 pycrypto pyyaml bcrypt pynacl geoip xlrd pillow==5.3.0 prompt-toolkit==2.0.9 asn1tools)

# this is the name of the user that ran this scrip as root using 'sudo'
# which will be the recommended way.
SUDO_USER=${SUDO_USER:-root}
AS_USER="sudo -u $SUDO_USER"
VENV="/usr/bin/env virtualenv"

PACK_MANAGER=""

exec 3>&1 4>&2 # backup fp
exec &> >(tee -ia "$INSTALLER_LOG")

function prompt() {
    echo -ne "\e[33m"
    read -s -p "$1" -n1 ANSWER;
    echo -e '\e[0m';
}

# logging
function log() {
    echo -e "\e[92m[$(date)]\e[0m \e[34m$@\e[0m"
}

function log_error() {
    echo -e "\e[1;102m[$(date)]\e[0m \e[1;31m$1\e[0m"
    exit -2;
}

function install_GeoLiteCity()
{
    log "Downloading GeoIP database..."
    wget -q -c "http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz" -O /tmp/GeoLiteCity.dat.gz;
    gunzip -c /tmp/GeoLiteCity.dat.gz > $ROOT_PATH/gui/WorldMap/GeoLiteCity.dat;
    rm -rf /tmp/GeoLiteCity.dat.gz;
}

function close_out_err_fd() {
    if ! [ -z $DEBUG ]; then
        exec 1> /dev/null 2>&1
    else
        echo -ne ''
    fi
}

function open_out_err_fd() {
    if ! [ -z $DEBUG ]; then
        exec 1<&3
        exec 2<&4
    else
        echo -ne ''
    fi
}

function check_root()
{
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root, exiting."
    fi
}

function install_system_packages()
{

    if [ -x "$(command -v apt-get)" ] ; then
        #Ubuntu/Debian system
        log "The following packages will have to be installed/updated in your system: " "${SYSTEM_PACKAGES[@]}" "${APT_PACKAGES[@]}"
        prompt "Continue? (Y/n)"
        ANSWER=${ANSWER:-Y}
        if [[ $ANSWER =~ ^[Yy]$ ]]; then
            log "Trying to install system packages via apt-get..."
            close_out_err_fd
            apt-get update || true
            apt-get install -y "${SYSTEM_PACKAGES[@]}"
            apt-get install -y "${APT_PACKAGES[@]}"
            open_out_err_fd
        else
            log_error "Exiting installation"
        fi

    elif [ -x "$(command -v yum)" ] ; then
        #Fedora/RedHat system
        log "The following packages will have to be installed/updated in your system: ${SYSTEM_PACKAGES[@]} ${YUM_PACKAGES[@]}."
        prompt "Continue? (Y/n)"
        ANSWER=${ANSWER:-Y}
        if [[ $ANSWER =~ ^[Yy]$ ]]; then
            log "Trying to install system packages via yum..."
            close_out_err_fd
            yum -y update || true
            yum install -y "${SYSTEM_PACKAGES[@]}"
            yum install -y "${YUM_PACKAGES[@]}"
            open_out_err_fd
        else
            log_error "Exiting installation."
        fi
    else
        #
        # this needs to be called without quotes because we
        log "Could not find apt-get/yum. This installer only supports for now Debian/Fedora based distros"
        exit -1
    fi
}

function choose_python_env_installation()
{
    prompt "Do you want to install python dependencies in a virtual environment (Y/n): "
    ANSWER=${ANSWER:-Y}

    if [[ $ANSWER =~ ^[Nn]$ ]]; then
        log "Using system environment ..."
        PIP=$(which pip)
        #change virtualenv path to /usr
        VIRTUAL_ENV=""
        VENV_PATH="/usr"
        #we need root privs
        AS_USER="sudo"
        PYTHON_BIN=$(which python)
    else
        log "Setting up a virtual environment ..."
        # we need to be sure we blow out PYTHONHOME if it's set.
        close_out_err_fd
        unset PYTHONHOME
        # cleaning out the venv path (in case of re-use)
        rm -rf "$VENV_PATH"
        # building virtualenv
        $AS_USER $VENV "$VENV_PATH"
        # setting variables that bin/activate would set
        VIRTUAL_ENV="$VENV_PATH"
        PYTHON_BIN="$VENV_PATH/bin/python"
        PATH="$VIRTUAL_ENV/bin:$PATH"
        PIP="$VENV_PATH/bin/pip"
        open_out_err_fd
    fi

    PATH="$VIRTUAL_ENV/bin:$PATH"

}

function install_python_packages()
{
    log "Installing Python packages ..."

    close_out_err_fd
    # upgrading pip, setuptools
    $AS_USER $PIP install -U "pip";
    $AS_USER $PIP install -U "setuptools"


    $AS_USER $PIP install "${PIP_PACKAGES[@]}"

    # this was useful during testing but likely isn't
    # necessary now, however it doesn't hurt to stay.
    # if [ -L $VENV_PATH/bin/python2.7-config ]; then
    #     rm $VENV_PATH/bin/python2.7-config
    # else
    #     ln -s $VENV_PATH/bin/python-config $VENV_PATH/bin/python2.7-config
    # fi

    open_out_err_fd
}

function download_compile_install_packages()
{
    declare -A URLs
    URLs=(["https://download.gnome.org/sources/pygtk/2.24/pygtk-2.24.0.tar.bz2"]="cd1c1ea265bd63ff669e92a2d3c2a88eb26bcd9e5363e0f82c896e649f206912"
          ["https://ftp.gnome.org/pub/GNOME/sources/pygobject/2.28/pygobject-2.28.7.tar.xz"]="bb9d25a3442ca7511385a7c01b057492095c263784ef31231ffe589d83a96a5a"
          ["https://cairographics.org/releases/py2cairo-1.10.0.tar.bz2"]="d30439f06c2ec1a39e27464c6c828b6eface3b22ee17b2de05dc409e429a7431"
          ["http://archive.ubuntu.com/ubuntu/pool/universe/v/vte/vte_0.28.2.orig.tar.xz"]="86cf0b81aa023fa93ed415653d51c96767f20b2d7334c893caba71e42654b0ae"
          ["http://archive.ubuntu.com/ubuntu/pool/universe/v/vte/vte_0.28.2-5ubuntu4.debian.tar.xz"]="f50ead3db07cf55a6ecd7ecd732aa5404d980b8acc20bba5d2303417f74e41ce"
          ["https://ftp.gnome.org/pub/GNOME/sources/libglade/2.6/libglade-2.6.4.tar.bz2"]="64361e7647839d36ed8336d992fd210d3e8139882269bed47dc4674980165dec"
         )

    # note the $AS_USER here: we want to make sure that the non-root user can read/write in the temporary directory
    # remember that this script is running as root.
    TMPDIR=$($AS_USER mktemp -d)

    # download and verify checksums
    for url in "${!URLs[@]}"
    do
        (
            cd $TMPDIR
            FILENAME="${url##*/}"

            log "Downloading $FILENAME..."
            close_out_err_fd
            $AS_USER wget "$url" -O "$FILENAME"
            open_out_err_fd
            # verify file was downloaded
            if ! [ -f "$FILENAME" ]; then
                log "Download error. Quitting installer."
                exit -1
            fi

            # verify checksums
            SHASUM=$(sha256sum "$FILENAME"|awk '{print $1}')
            log "Expected   SHASUM: ${URLs[$url]}"

            if [[ $SHASUM != ${URLs[$url]} ]]; then
               log "Calculated checksums do not match expected. Quitting installer."
               exit -1
            fi
        )
    done

    #
    # at this point, files are downloaded and checksums exist
    #

    # array of packages name with a specifc order
    array_filenames=("py2cairo-1.10.0.tar.bz2" "pygobject-2.28.7.tar.xz" "libglade-2.6.4.tar.bz2" "pygtk-2.24.0.tar.bz2" "vte_0.28.2.orig.tar.xz")

    # forcing the package installation to be done in a specific order.
    for FILENAME in ${array_filenames[@]};
    do
	    log "Processing $FILENAME..."
	    close_out_err_fd
            (
                # at this point, $FILE contains the package that this loop is executing for.
                cd "$TMPDIR"
                #FILENAME=$(basename "$FILE")

                # not the most efficient way of getting the directory name, but it's sensible in this case.
                TOPLEVELDIRNAME=$(tar --list -f "$FILENAME" |head -1|cut -d "/" -f 1)
                $AS_USER tar -xf "$FILENAME"
                case "$FILENAME" in
                    "py2cairo-1.10.0.tar.bz2")
                        cd "$TOPLEVELDIRNAME"
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" libtoolize --force
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" aclocal
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" autoheader
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" autoconf
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" ./waf ./configure "--prefix=$VENV_PATH"#|| true
                        sleep 3;
                        #trick to fix a bug
                        $AS_USER  sed -i 's/conf\.env\.PYTHON+\[conf/\[conf/g' ".waf-1.6.3-3c3129a3ec8fb4a5bbc7ba3161463b22/waflib/Tools/python.py"
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" $PYTHON_BIN waf configure "--prefix=$VENV_PATH"
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" $PYTHON_BIN waf build
                        $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" $PYTHON_BIN waf install
                        ;;

                    "pygobject-2.28.7.tar.xz")
                        cd "$TOPLEVELDIRNAME"
                        $AS_USER ./configure "--prefix=$VENV_PATH"
                        $AS_USER make
                        $AS_USER make install
                        ;;
                    "libglade-2.6.4.tar.bz2")
                        cd "$TOPLEVELDIRNAME"
                        $AS_USER ./configure "--prefix=$VENV_PATH" "PKG_CONFIG_PATH=$VENV_PATH/lib/pkgconfig"
                        $AS_USER make
                        $AS_USER make install
                        ;;
                    "pygtk-2.24.0.tar.bz2")
                        cd "$TOPLEVELDIRNAME"
                        $AS_USER ./configure "--prefix=$VENV_PATH" "PKG_CONFIG_PATH=$VENV_PATH/lib/pkgconfig"
                        $AS_USER make
                        $AS_USER make install
                        ;;
                    "vte_0.28.2.orig.tar.xz")
                        #skip in RH systems
                        #if ! [ -x "$(command -v yum)" ] ; then
                            # this one is a bit more complicated, sadly, has hardcoded filenames.
                            cd "$TOPLEVELDIRNAME"
                            UBUNTU_VTE_FILE="vte_0.28.2-5ubuntu4.debian.tar.xz"
                            $AS_USER tar -xvf "../$UBUNTU_VTE_FILE"
                            while read p
                            do
                                $AS_USER patch -p1 < "./debian/patches/$p"
                            done < ./debian/patches/series

                            $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" ./configure "--prefix=$VENV_PATH" "PKG_CONFIG_PATH=$VENV_PATH/lib/pkgconfig"
                            $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" make
                            $AS_USER "PATH=$VIRTUAL_ENV/bin:$PATH" make install
                        #fi
                        ;;
                esac
            )
        done
        open_out_err_fd


#    done
}

log "This will begin the Python CANVAS dependency installation process. [Press enter to continue]"; read -s -n1;

#check if we have the rigth permissions
check_root

install_system_packages

choose_python_env_installation

install_python_packages

download_compile_install_packages

log "All dependencies installed, now you can run: $ROOT_PATH/runcanvas.sh"
