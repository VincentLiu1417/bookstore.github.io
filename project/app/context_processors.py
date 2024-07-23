from .forms import BookSearchForm

def search_form(request):
    return {
        'search_form': BookSearchForm()
    }
