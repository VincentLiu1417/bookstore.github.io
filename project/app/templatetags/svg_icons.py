from django import template
from django.templatetags.static import static

register = template.Library()

@register.simple_tag
def svg_icon(icon_name):
    return static(f'icons/{icon_name}.svg')
