# Copyright (c) 2017 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Michael Fincham <michael.fincham@catalyst.net.nz>
# Author: Filip Vujicic <filip.vujicic@catalyst.net.nz>
# Author: Sam Banks <sam.banks@catalyst.net.nz>

from django.contrib import admin
from django.db.models import Count

from .models import *

class BinaryPackageInline(admin.TabularInline):
    model = BinaryPackage
    extra = 0
    readonly_fields = ('source_package',)
    fields = ('package', 'safe_version', 'architecture')

class SourcePackageInline(admin.TabularInline):
    model = SourcePackage
    extra = 0
    fields = ('package', 'release', 'safe_version')

class VulnerabilityInline(admin.TabularInline):
    model = Advisory.vulnerabilities.through
    extra = 0

class AdvisoryAdmin(admin.ModelAdmin):
    inlines = [VulnerabilityInline, SourcePackageInline, BinaryPackageInline]
    list_filter = ['issued', 'source']
    search_fields = ['upstream_id']
    list_display = ['upstream_id', 'short_description', 'source_package_names', 'source', 'issued']
    ordering = ['-issued']

class VulnerabilityAdmin(admin.ModelAdmin):
    list_filter = ['first_seen']
    search_fields = ['upstream_id']
    list_display = ['upstream_id', 'advisory_count', 'first_seen']
    ordering = ['-first_seen']

    def get_queryset(self, request):
        qs = super(VulnerabilityAdmin, self).get_queryset(request)
        return qs.annotate(advisory_count=Count('advisories'))

    def advisory_count(self, inst):
        return inst.advisory_count
    advisory_count.admin_order_field = 'advisory_count'

admin.site.register(Advisory, AdvisoryAdmin)
admin.site.register(Vulnerability, VulnerabilityAdmin)
