import sys
import numpy as np
import matplotlib.pyplot as plt
from sklearn import svm
from features import *

def main():
    filesTxt = sys.argv[1]
    fileList = getFiles(filesTxt)

    timeDict, ipLenDict, burstDict, traceList = getFeatures(fileList)
    print(traceList)


if __name__ == '__main__':
    main()