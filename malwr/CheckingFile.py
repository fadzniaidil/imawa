#! /usr/bin/python2
import pefile
import os
import array
import math
import pickle
import time
# from sklearn.externals import joblib
import joblib
import sys
from .ModulePredict import data_extraction
from .XKendworld import pure_import
import pymongo
import hashlib

myclient = pymongo.MongoClient('DATABASE_URL')
mydb = myclient["DATABASE"]
mycol = mydb["COLLECTION"]

def checkpre(filepath):

    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'
    ))
  
    with open('classifier/features.pkl', 'rb') as f:
        features = pickle.load(f)

    data = data_extraction(repathfile(filepath))
    pe_features = list(map(lambda x:data[x], features))

    res= clf.predict([pe_features])[0]
    return (['Malicious', 'Legitimate'][res])
    
def hashcheck(filepath):
    pe = pefile.PE(repathfile(filepath))
    fp = open(repathfile(filepath),'rb')
    data = fp.read()
    return hashlib.md5(data).hexdigest()

def procedureXK001(filepath):

    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifierxk/classifierxk.pkl'
    ))
  
    with open('classifierxk/featuresxk.pkl', 'rb') as f:
        features = pickle.load(f)

    data = pure_import(repathfile(filepath))
    pe_features = list(map(lambda x:data[x], features))

    res= clf.predict([pe_features])[0]
    return (['Adware','Backdoor','Keylogger','Ransomware','Rootkit','Spyware','Trojan','Virus','Worm'][res])

def repathfile(filepath):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)) + filepath)

def savestorage(filepath):
    return os.remove(repathfile(filepath))

def sample_extraction(filepath):
    pe = pefile.PE(repathfile(filepath))
    fp = open(repathfile(filepath),'rb')
    data = fp.read()
    y = []
    
    y.append(len(data))
    if pe.FILE_HEADER.Machine == 0x14C:
        y.append("Architecture : 32 Bits Binary")
    elif pe.FILE_HEADER.Machine == 0x8664: 
        y.append("Architecture : 64 Bits Binary")

    y.append(hashlib.md5(data).hexdigest())
    y.append(hashlib.sha1(data).hexdigest())
    y.append(hashlib.sha256(data).hexdigest())
    val = pe.FILE_HEADER.TimeDateStamp
    y.append(time.asctime(time.gmtime(val)))

    return y

def db_saving(filepath):
    pe = pefile.PE(repathfile(filepath))
    fp = open(repathfile(filepath),'rb')
    data = fp.read()
    dbstr= {}

    dbstr["dataSize"] = len(data)

    if pe.FILE_HEADER.Machine == 0x14C:
        dbstr["arch"] = "32 Bits Binary"
    elif pe.FILE_HEADER.Machine == 0x8664:
        dbstr["arch"] = "64 Bits Binary"


    dbstr["md5"] = hashlib.md5(data).hexdigest()
    dbstr["sha1"] = hashlib.sha1(data).hexdigest()
    dbstr["sha256"] = hashlib.sha256(data).hexdigest()
    val = pe.FILE_HEADER.TimeDateStamp
    dbstr["timestamp"] =time.asctime(time.gmtime(val))

    if checkpre(filepath) == "Legitimate":
        dbstr['status'] = "Legitimate"
    else :
        dbstr['status'] = "Malicious"
        dbstr['type'] = procedureXK001(filepath)

    x = mycol.insert_one(dbstr)
    return dbstr
    