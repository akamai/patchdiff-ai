import pickle
from pathlib import Path

from common import Timer, console
from patch_downloader import get_os_data, cve_enrichment
from supervisor.gather_info import GatherInfoContext


@Timer()
def get_os_cvrf_data() -> tuple[str, int]:
    cache_os = Path('db/.os')

    if cache_os.exists():
        os_data = pickle.loads(cache_os.read_bytes())
    else:
        os_data = get_os_data.get_cvrf_product_name_and_id()
        cache_os.write_bytes(pickle.dumps(os_data))

    return os_data


@Timer()
def get_articles(context: GatherInfoContext):
    # TODO: Cache to disk
    metadata = cve_enrichment.report(context.cve_details.cve)

    articles = []
    product = next(filter(lambda x: x.get('productId') == context.os.id, metadata.products), None)
    if not product:
        # The CVE is not related to the provided os
        console.warning(f'[-] The product {context.os.name} is not affected by {context.cve_details.cve}')
        raise RuntimeError(f'The product {context.os.name} is not affected by {context.cve_details.cve}')

    for article in filter(lambda x: x.get('article') and x.get('supercedence'), product.get('articles')):
        articles.append(article)

    if not articles:
        # There is no 2 consecutive KBs
        # TODO: handle first update after feature release
        raise RuntimeError('Cannot find the CVE articles')

    article = next(filter(lambda x: x.get('type') == 'security update', articles), None)
    if article is None:
        article = articles[0]

    context.KB.base = product.get('baseVersion')
    context.KB.current = 'KB' + article.get('article')
    context.KB.previous = 'KB' + article.get('supercedence')
    context.cve_details.description = metadata.description
    context.cve_details.msrc_report = metadata

    console.info(f'[+] Get {context.cve_details.cve} articles, patched in {context.KB.current} and replace {context.KB.previous}.')
