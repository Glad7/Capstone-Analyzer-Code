from pikepdf import Pdf
import os
import sys

#Checks to see if there is an argument for a PDF file
#TO DO: Check if it's an actual PDF file
def fileCheck():
    if len(sys.argv) < 2:
        print('Error, please provide a PDF file.')
        exit()

#grabs and returns the number of pages in the PDF as a list
def pageCount(pdf):
    pages = []
    for pageNum in range(len(pdf.pages)):
        pages.append(pageNum)
    return pages    

#calls the pdf-parser.py CLI tool
#TO DO: See what commands are useful for analyzing contents for malware
def pdf_parser(fileName):
    stream = os.popen('python pdf-parser.py -a ' + fileName, 'r')
    output = stream.read()
    print(output)

    keywords = ['/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/RichMedia', '/Launch', '/EmbeddedFile', '/XFA', '/URI']
    my_keywords = []
    for word in keywords:
        if word in output:
            my_keywords + word
    print(my_keywords)

#calls the pdfid CLI tool
#will probably remove this, because pdf-parser can do the same thing
def pdfid(fileName):
    pdfid_Stream = os.popen('python ./pdfid/pdfid.py ' + fileName, 'r')
    pdfid_output = pdfid_Stream.read()
    print(pdfid_output)

def Main():
    fileCheck()
    pdf = Pdf.open(sys.argv[1])
    pages = pageCount(pdf)

    #pdfid(sys.argv[1])

    pdf_parser(sys.argv[1])

Main()