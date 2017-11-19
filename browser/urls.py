from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^table$', views.AdvisoryTableView.as_view(), name='table'),
    url(r'^cve_table$', views.VulnerabilityTableView.as_view(), name='cve_table'),
    url(r'^advisory/(.*)$', views.advisory, name='advisory_detail'),
    url(r'^vulnerability/(.*)$', views.vulnerability, name='vulnerability_detail'),
    url(r'^cves$', views.cves, name='cves'),
]
