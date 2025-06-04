
##*Important:**
**after any structural or import changes, update this section!



** Script/Module (from src import src_...) > Local Imports | Standard Python Modules  :


| **main.py** >
 src_menus, src_status, src_socksify, src_proxychains, src_tor, src_dnsson, src_proxyson, src_updater, src_uninstall, src_utils, config || os, sys, time, datetime 

| **src_dnsson.py** >
 src_menus, src_status, src_utils, src_tor, src_remover, src_installer || re, os 

| **src_installer.py** >
 src_tor, src_remover, src_utils, src_psiphon || os, subprocess, tempfile, re, shutil |

| **src_menus.py** >
 src_utils, src_status, config || sys |

| **src_proxychains.py** >
 src_utils, src_status, src_remover, src_installer, src_tor, src_menus || os, re, shutil, subprocess, time, uuid |

| **src_proxyson.py** >
 src_utils, src_menus, src_status, src_remover, src_tor || os, re  |

| **src_remover.py** >
 src_utils, src_psiphon || os, sys, time, datetime, subprocess |

| **src_socksify.py** > src_utils, src_remover, src_installer, src_tor, src_menus, src_status, src_proxyson, src_dnsson || os, re, time, subprocess |

| **src_status.py** >
 src_utils, src_tor, src_psiphon || os, re, signal, subprocess, sys, threading, time, typing.List, typing.Dict, json |

| **src_tor.py** >
 src_utils, src_menus, src_status, src_installer, src_remover, src_dnsson, src_proxyson, src_socksify, src_proxychains || os, re, subprocess, shutil, uuid, socket, time |

| **src_uninstall.py** > 
src_menus, src_remover, src_utils || sys, os, shutil |

| **src_updater.py** >
 config, src_utils || os, sys, requests, tarfile, tempfile, shutil, datetime, from pathlib import Path |


| **src_utils.py** >
 None || os, subprocess, shutil, socket, random, time, re, json, contextlib.contextmanager, select, ipaddress, requests, from urllib.parse import urlparse |