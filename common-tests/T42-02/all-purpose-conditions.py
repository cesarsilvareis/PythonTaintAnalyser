#This test has 2 vulnerability patterns. 
#They are the same other than the fact that one considers implicit taints and the other does not.
a = b = c = d = e = 0
a = source_1(source_2())
f = source_4()
#a is double tainted
if(b and c or not -d):
    #implicit taint from source 3
    if(source_3()):
        b = 5
    else:
        c = 5
        f = sanitizer_1(f)
elif(d < e or e == b):
    d = 5
else:
    e = 7
#both vulnerability A and B are the same but B considers implicit taints
#only the implicit flow is sanitized
b = sanitizer_1(b)
sink_1(a, b, c, f)