a = b = c = c.go = 0
a.x = 0
a.x.y = fee("fi fo fum")
a.x.y.z = 0
#by now anything that starts with a.x.y is tainted
jack(a.x.y.z)
#now lets taint a to see if it propagates to the rest
a = fi("fo fum")
jack(a.x.y.z)
#now we clean it up and see if it still remains
a = a.x.y = bean(a)
jack(a.x.y.z)
#if its uninitialized, it should still be tainted though
jack(b.c)
#a source can be an attribute
jack(b.fo.fum)
#and a sink can be an attribute too
c.go.jill(fo())