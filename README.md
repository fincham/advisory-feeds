# advisory-feeds

**This is a bit of an ugly fork of some open source code we've been building as part of a larger project at work, forked for BSides Wellington 2017. Once we decide how to structure the project better this repo will be replaced by a link to the official one over at [Catalyst](https://github.com/catalyst/).**

## What is this?

The Django application in `/advisories` tries to collect actionable, machine readable information about "security advisories" issued by Linux distributions. Currently it knows how to get information about Ubuntu USNs and Debian DSAs and DLAs.

It then stores a list of affected source packages, binary packages, CVEs and some other metadata about each advisory to aid in building systems that generate reports, assist in patching large server fleets etc. 

There's also an example Django application bundled in `/browser`, and a project in `/advisorybrowser` to allow basic public browsing of the data collected by the `advisories` app. There is a live demo of this running at https://tools.hotplate.co.nz/advisories/, updated nightly.

## How do I set it up?

`python-apt` isn't installable easily from pip (it has silent deps on things which are not in PyPi), so you may need to:

    ln -s /usr/lib/python3/dist-packages/apt* $VIRTUAL_ENV/lib/python*/site-packages
    
And install the `python-apt` package outside of the virtualenv.

Once the application is working you'll want to run `manage.py updateadvisories` periodically to update your database. Probably once every 24 hours is sufficient and shouldn't place undue burden on the upstream information sources.

## What is this for?

If you need to develop automated reporting on the "patch state" of large numbers of hosts, or if you want to make the process of patching them simpler then it's useful to have vulnerability information in a machine readable state. See also [osquery-controller](https://github.com/fincham/osquery-controller) for a way to get information about what packages you actually have installed.

We would be interested to see what you can do with this data!
