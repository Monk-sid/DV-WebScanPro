import time
import sys
from urllib.parse import urldefrag
from utils import get_session, extract_links, extract_forms, normalize_url, is_same_domain
from tqdm import tqdm


class Crawler:
    def __init__(self, base_url, max_pages=200, delay=0.2, session=None):
        # Normalize base_url safely as string and strip trailing slash
        self.base = normalize_url(str(base_url).rstrip('/'))
        self.max_pages = max_pages
        self.delay = delay
        self.session = session or get_session()
        self.visited = set()
        self.queue = [self.base]
        self.pages = {}
        self.forms = {}

    def crawl(self):
        pbar = tqdm(total=self.max_pages, desc="Crawling")
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.pop(0)
            if current_url in self.visited:
                continue
            if not is_same_domain(self.base, current_url):
                continue
            try:
                r = self.session.get(current_url, timeout=10, allow_redirects=True)
                html = r.text
            except Exception as e:
                print(f"failed to fetch {current_url}: {e}", file=sys.stderr)
                self.visited.add(current_url)
                continue
            self.visited.add(current_url)
            self.pages[current_url] = html

            forms = extract_forms(html, current_url)
            if forms:
                self.forms[current_url] = forms

            links = extract_links(html, current_url)
            for link in links:
                clean_link = normalize_url(str(urldefrag(link)[0]).rstrip('/'))
                if (
                    clean_link
                    and clean_link not in self.visited
                    and clean_link not in self.queue
                    and is_same_domain(self.base, clean_link)
                ):
                    self.queue.append(clean_link)

            pbar.update(1) 
            time.sleep(self.delay)
        pbar.close()

if __name__ == "__main__":
    start_url = "http://localhost:8080/"
    crawler = Crawler(start_url, max_pages=50, delay=0.5)
    crawler.crawl()
    print("\nVisited Pages:")
    for url in crawler.visited:
        print(url)
