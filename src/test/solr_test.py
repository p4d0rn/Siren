from urllib.parse import urlparse, urljoin

from sniper.java.Solr import Solr

solr = Solr("http://xxx/solr")
solr.check_ssrf()
