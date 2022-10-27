from pikepdf import Pdf
import os
from collections import deque #supports rotate()
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
    
    # Finds obfuscated JS code and then deobfuscates it by calling spider-monkey (/js)
    # Deobfuscated JS STILL NEEDS TO BE PARSED FOR IDENTIFIERS which would satisfy signatures #6-9.
    def deobfuscateJS(self, fileName):
        stream = os.popen('python pdf-parser.py -s javascript ' + fileName, 'r')       
        output = stream.read()
        stream.close()
        output = (output.split('obj'))  
        # Remove the warning message
        check_string = 'This program has not been tested with this version of Python'
        result = any(check_string in sub for sub in output)
        
        if result == True:
            output = deque(output)
            output.popleft()
            output = list(output) # Even though output is a list, it outputs like a normal string not a list
        
        
        newStr = ''.join(output) #Re-construct the normal looking output.
        newStr = newStr.split(' ')  #Parse the normal looking output.
        objectIndex = newStr.index('/JS') #Find the position of the string /JS.
        objectIndex = newStr[objectIndex+1] #Find the object number /JS is referencing.
        objectIndex = str(objectIndex)  #Turn the object number into a string.
        runCmd = f'python pdf-parser.py -o {objectIndex} {fileName}' #Create the command that will be ran.
    
        #Run the command
        runCmd = os.popen(runCmd, 'r')
        stream = runCmd.read()

        # Remove the warning message
        # Calling this the second time doesn't remove the warning message for unknown reason

        #check_string = 'This program has not been tested with this version of Python'
        #result = any(check_string in sub for sub in stream)
        
        #if result == True:
        #    stream = deque(stream)
        #    stream.popleft()
        #    stream = list(stream)

        #Search this new output for any encodings.
        newStr = stream.split(' ')  #Parse the normal looking output.
        
        # If /Filter exists then run the decode option
        if newStr.index('/Filter') != False:
            runCmd = f'python pdf-parser.py -o {objectIndex} -f {fileName}'
            runCmd = os.popen(runCmd, 'r') 
            stream = runCmd.read()
            print (stream)
        
        ##
        ## Still need to code to parse for identifiers.
        ##

        retcode = os.popen(f'python pdf-parser.py -o {objectIndex} -f -d five.js {fileName}') 
        stream = retcode.read() #os.popen will error if the stream is not read().
        
        # Don't add 'r', or 'w' in os.popen if we don't intend to do anything with the stream.
        # A.k.a in situations where we only want to call the command to open a file.
        # Adding 'r' or 'w' in this situation breaks the pipe for some reason.
        spiderMonkey = str('./js')    # Path to where spidermonkey program is located. 
        retcode = os.popen(f'{spiderMonkey} five.js')
        stream = retcode.read()

        # Look at the deobfuscated javascript.
        # Spidermonkey will always output to a file called eval.001.log.
        deobfuscatedJs = open('eval.001.log', 'r')
        print(deobfuscatedJs.read())
    
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
