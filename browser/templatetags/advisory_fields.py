import textwrap
import re

from django import template
from django.conf import settings
from django.template.defaultfilters import stringfilter
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe
from django.core.urlresolvers import reverse

register = template.Library()

@register.filter
@stringfilter
def advisory_source(value):
    return value.capitalize()

@register.filter
@stringfilter
def ignore_none(value):
    if value == 'None':
        return ''

    return value

@register.filter
def sortedlist(value):
    return ", ".join(sorted(value))

@register.filter(needs_autoescape=True)
@stringfilter
def paragraphbreaks(value, autoescape=True):
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x

    value = textwrap.dedent(value).replace('\r\n', '\n') # fix windows linebreaks

    result = '<p>%s</p>' % '</p><p>'.join(esc(value).split('\n\n'))
    result = re.sub(r"(CVE-[0-9]+-[0-9]+)", r'<a href="%s\1">\1</a>' % reverse('vulnerability_detail', args=['']), result)
    result = re.sub(r"(DSA-[0-9]+-[0-9]+)", r'<a href="%s\1">\1</a>' % reverse('advisory_detail', args=['']), result)
    result = re.sub(r"(DLA-[0-9]+-[0-9]+)", r'<a href="%s\1">\1</a>' % reverse('advisory_detail', args=['']), result)
    result = re.sub(r"(USN-[0-9]+-[0-9]+)", r'<a href="%s\1">\1</a>' % reverse('advisory_detail', args=['']), result)
    return mark_safe(result)
