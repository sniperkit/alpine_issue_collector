from bs4 import BeautifulSoup
import urllib2
import json
import sys


class MyData:
    def __init__(self, package, version):
        self.package = package
        self.version = version
    def to_JSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)
    def __repr__(self):
        return "Pkg= %s 	Version= %s\n" % (self.package, self.version)



def numberOfPagesFromAlpine():
	url = urllib2.urlopen("http://pkgs.alpinelinux.org/packages")
	content = url.read()
	soup = BeautifulSoup(content)
	pages = soup.findAll("ul", { "class" : "pagination" })
	nums = []
	for page in pages:
		data = page.findAll('li')
		for d in data:
			a = d.find("a", href=True)
			x = a["href"].split("=")
			nums.append(int(x[1]))
	return max(nums)

def parseAlpinePackagesURLs(fp):
    numberOfPages = numberOfPagesFromAlpine()
    dictionary = {}
    for i in range (1, numberOfPages):
        print('Processing page: ' + str(i) + ' only ' + str(numberOfPages-i) + ' remaining')
        url = urllib2.urlopen("http://pkgs.alpinelinux.org/packages?page="+str(i))
        content = url.read()
        soup = BeautifulSoup(content)
        packages = []
        versions = []
        packages = soup.findAll("td", { "class" : "package" })
        versions = soup.findAll("td", { "class" : "version" })
        results = []

        for j in range (0, len(packages)):
            dictionary.setdefault(packages[j].find("a").contents[0],[]).append(versions[j].find("a").contents[0])
            #m = MyData(package= packages[j].find("a").contents[0], version=versions[j].find("a").contents[0])
            #results.append(m)
            #fp.write(m.to_JSON()+",\n")
            j=j+1
    fp.write(json.dumps(dictionary))

file_path = '../data/packages_versions.json'

try:
    fp = open(file_path, 'a+')
except IOError:
    # If not exists, create the file
    fp = open(file_path, 'w+')

parseAlpinePackagesURLs(fp)


