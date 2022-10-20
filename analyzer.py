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

    def jsSearch(self, fileName):
        stream = os.popen('python pdf-parser.py -s /JavaScript ' + fileName, 'r')    
        output = stream.read().splitlines()
        for line in output:
            if "obj" in line:
                return line

        return 0

    def flateDecodeSearch(self, fileName, objNum):
        stream = os.popen('python pdf-parser.py -o ' + objNum + ' ' + fileName)
        output = stream.read().splitlines()
        for line in output:
            if "/FlateDecode" in line:
                return True

        return False            

#the class that holds all of the signature detection functions
class signatures():
    
    # checks to see if signature one or two is present
    def sig_one_and_two(self, fileName, pdf):
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
                    #immediatly returns for signature 2 is obfuscation is found
                    if(output[i][-1] == ")"):
                        jsObfuscatedFlag = 1
                        return 2
                    jsFlag = 1

            elif "/AA" in output[i]:
                if(output[i][-1] != "0"):
                    aaFlag = 1

            elif "/OpenAction" in output[i]:
                if(output[i][-1] != "0"):
                    oaFlag = 1

            elif "/AcroForm" in output[i]:
                if(output[i][-1] != "0"):
                    acroFlag = 1

        #final check for signature 1
        if jsFlag == 1 or jsObfuscatedFlag == 1:
            if aaFlag == 1 or oaFlag == 1 or acroFlag == 1:
                if len(pageCount(pdf)) == 1:
                    return 1
        return 0

    def sig_three(self, fileName):
        cmd = pdf_parser()

        if cmd.jsSearch(fileName) != 0:
            obj = cmd.jsSearch(fileName)
        else:
            return 0

        objNum = ''

        for i in range(4, len(obj)):
            if obj[i].isnumeric():
                objNum += obj[i]

            if not obj[i].isnumeric():
                break

        if cmd.flateDecodeSearch(fileName, objNum):
            return True

        return False                

def main():
    fileCheck()
    pdf = Pdf.open(sys.argv[1])
    pages = pageCount(pdf)

    file = (sys.argv[1])

    cmd = pdf_parser()
    signature = signatures()

    #cmd.stats(file)
    #cmd.encoding(file)
    if signature.sig_one_and_two(file, pdf) == 1:
        print("WARNING, SIGNATURE 1 TRIGGERED")
    elif signature.sig_one_and_two(file, pdf) == 2:
        print("WARNING, SIGNATURE 2 TRIGGERED") 
    elif signature.sig_three(file):
        print('WARNING, SIGNATURE 3 TRIGGERED')
    else:
        print('The PDF file is safe to open')

if __name__ == "__main__":
    main()