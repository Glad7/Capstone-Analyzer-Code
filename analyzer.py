from pikepdf import Pdf
import os
import sys
#import re

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

#pdfid CLI tool to get info for signatures
def pdfid(fileName):
    pdfid_Stream = os.popen('python ./pdfid/pdfid.py ' + fileName, 'r')
    output = pdfid_Stream.read().splitlines()
    return output[2:-2]

#An instance of /AA or /OpenAction in conjunction with /JavaScript is one indication (95%) of malware
#calls the pdf-parser.py CLI tools with various options
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

    
#the class that holds all of the signature detection functions
class signatures():
    
    # checks to see if signature one or two is present
    def one_and_two(self, fileName, pdf):
        output = pdfid(fileName)

        jsFlag = 0
        jsObfuscatedFlag = 0
        aaFlag = 0
        oaFlag = 0
        acroFlag = 0

        for i in range(0, len(output)):
            #print(output[i])
            if "JavaScript" in output[i]:
                if(output[i][-1] != "0"):
                    if(output[i][-1] == ")"):
                        jsObfuscatedFlag = 1
                        print("Javascript found in file with " + output[i][-2] + " obfuscated instance(s) and " + output[i][-4] + " non-obfuscated instance(s)")
                        return 2
                    print("Javascript found in file with " + output[i][-1] + " instance(s)")
                    jsFlag = 1
            elif "/AA" in output[i]:
                if(output[i][-1] != "0"):
                    aaFlag = 1
                    print("Automatic actions found in file with " + output[i][-1] + " instance(s)")
            elif "/OpenAction" in output[i]:
                if(output[i][-1] != "0"):
                    oaFlag = 1
                    print("Open actions found in file with " + output[i][-1] + " instance(s)")        
            elif "/AcroForm" in output[i]:
                if(output[i][-1] != "0"):
                    acroFlag = 1
                    print("Acro forms found in file with " + output[i][-1] + " instance(s)")

        if jsFlag == 1 or jsObfuscatedFlag == 1:
            if aaFlag == 1 or oaFlag == 1 or acroFlag == 1:
                if len(pageCount(pdf)) == 1:
                    print("Only one page in the PDF document")
                    return 1
        return 0

def Main():
    fileCheck()
    pdf = Pdf.open(sys.argv[1])
    pages = pageCount(pdf)

    file = (sys.argv[1])

    cmd = pdf_parser()
    signature = signatures()

    #cmd.stats(file)
    #cmd.encoding(file)
    if signature.one_and_two(file, pdf) == 1:
        print("WARNING, MALWARE LIKELY EMBEDDED")
    elif signature.one_and_two(file, pdf) == 2:
        print("WARNING, OBFUSCATED JAVASCRIPT DETECTED") 

Main()