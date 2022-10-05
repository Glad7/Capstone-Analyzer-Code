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

#TO DO: See what commands are useful for analyzing contents for malware
#An instance of /AA or /OpenAction in conjunction with /JavaScript is one indication (95%) of malware
#calls the pdf-parser.py CLI tools with various options
#calls the pdfid.py CLI tool
class pdf_parser():

    # display stats for pdf document
    def stats(self, fileName):
        stream = os.popen('python pdf-parser.py -a ' + fileName, 'r')
        output = stream.read()
        print(output)

    # string to search in indirect objects (except streams)
    # searches for string 'Encoding'
    # Returns: prints the entire object where the string was found
    def encoding(self, fileName):
        stream = os.popen('python pdf-parser.py --search=Encoding ' + fileName, 'r')       
        output = stream.read()
        print(output)

    # calls the pdfid CLI tool
    # pdfid scans a file to look for certain PDF keywords
    def pdfid(self, fileName):
        pdfid_Stream = os.popen('python ./pdfid/pdfid.py ' + fileName, 'r')
        pdfid_output = pdfid_Stream.read()
        print(pdfid_output)



def Main():
    fileCheck()
    pdf = Pdf.open(sys.argv[1])
    pages = pageCount(pdf)

    file = (sys.argv[1])

    cmd = pdf_parser()

    cmd.stats(file)
    cmd.encoding(file)
    cmd.pdfid(file)

Main()