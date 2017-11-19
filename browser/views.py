from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse

from advisories.models import *
from django_datatables_view.base_datatable_view import BaseDatatableView

from django.core.urlresolvers import reverse
from django.utils import formats
from django.conf import settings
from django.db.models import Q

import datetime
import collections

def index(request):
    try:
        with open("%s/advisory_cache/timestamp" % settings.BASE_DIR, 'r') as timestamp:
            updated = str(datetime.datetime.fromtimestamp(int(timestamp.readline()))).strip('.')
    except:
        updated = "never"
    advisory_count = Advisory.objects.all().count()
    recent_advisories = Advisory.objects.order_by('-issued').all()[0:5]
    recent_packages = SourcePackage.objects.order_by('-advisory__issued').all()[0:5]
    recent_vulnerabilities = Vulnerability.objects.order_by('-first_seen').all()[0:5]
    return render(request, 'browser/index.html', {'recent_advisories': recent_advisories, 'recent_packages': recent_packages, 'recent_vulnerabilities': recent_vulnerabilities, 'advisory_count': advisory_count, 'updated': updated})

def cves(request):
    try:
        with open("%s/advisory_cache/timestamp" % settings.BASE_DIR, 'r') as timestamp:
            updated = str(datetime.datetime.fromtimestamp(int(timestamp.readline()))).strip('.')
    except:
        updated = "never"
    vulnerability_count = Vulnerability.objects.all().count()
    return render(request, 'browser/cves.html', {'vulnerability_count': vulnerability_count, 'updated': updated})

def advisory(request, upstream_id):
    advisory = get_object_or_404(Advisory, upstream_id=upstream_id) 

    # XXX this seems like a horrible way to do this but the triple nested regroup in the template didn't work

    binary_packages = collections.defaultdict(dict)

    for package in advisory.binarypackage_set.all():
        package_key = "%s %s" % (package.package, package.safe_version)

        if package_key not in binary_packages[package.release]:
            binary_packages[package.release][package_key] = {'package': package, 'architectures': []}

        binary_packages[package.release][package_key]['architectures'].append(package.architecture)

    return render(request, 'browser/advisory.html', {'object': advisory, 'advisory': advisory, 'binary_packages': dict(binary_packages), 'aptget_command': 'apt --only-upgrade install', })

def vulnerability(request, upstream_id):
    vulnerability = get_object_or_404(Vulnerability, upstream_id=upstream_id) 

    return render(request, 'browser/vulnerability.html', {'vulnerability': vulnerability})

class AdvisoryTableView(BaseDatatableView):
    model = Advisory
    order_columns = ['upstream_id', '', '', '', 'source', 'issued']
    max_display_length = 500

    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
            if search.upper().startswith('CVE-'):
                vuln = Vulnerability.objects.filter(upstream_id__istartswith=search.upper())
                qs = qs.filter(vulnerabilities__in=vuln)
            else:
                qs = qs.filter(search_keywords__icontains=search)
        return qs

    def prepare_results(self, qs):
        json_data = []
        for item in qs:
            json_data.append([
                '<a href="%s">%s</a>' % (reverse('advisory_detail', args=[item.upstream_id]), item.upstream_id), 
                item.short_description,
                item.source_package_names(),
                ", ".join(sorted(['<a href="%s">%s</a>' % (reverse('vulnerability_detail', args=[vulnerability.upstream_id]), vulnerability.__str__()) for vulnerability in item.vulnerabilities.all()])),
                item.source.capitalize(),
                formats.date_format(item.issued, "Y-m-d")
            ])
        return json_data
   
class VulnerabilityTableView(BaseDatatableView):
    model = Vulnerability
    order_columns = ['upstream_id', '', '', 'first_seen']
    max_display_length = 500

    def filter_queryset(self, qs):
        search = self.request.GET.get(u'search[value]', None)
        if search:
                qs = qs.filter(Q(upstream_id__icontains=search) | Q(advisories__source__in=[search]) | Q(advisories__upstream_id__in=[search]))
        return qs

    def prepare_results(self, qs):
        json_data = []
        for item in qs:
            json_data.append([
                '<a href="%s">%s</a>' % (reverse('vulnerability_detail', args=[item.upstream_id]), item.upstream_id), 
                ", ".join(sorted(['<a href="%s">%s</a>' % (reverse('advisory_detail', args=[advisory.upstream_id]), advisory.__str__()) for advisory in item.advisories.all()])),
                item.source_list(),
                formats.date_format(item.first_seen, "Y-m-d")
            ])
        return json_data
   

