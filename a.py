import sys
import random

n=int(sys.argv[1])
N=int(sys.argv[2])

l=[int(random.random()*1e14) for _ in range(n)]

for m in l:
    print 'MAC '+':'.join(hex((m>>8*i)&255)[2:] for i in range(5,-1,-1))

proto=[17,1]
plen =24

for _ in range(N):
    ip = random.randint(1,1<<32)
    ps = random.randint(0,1<<16) 
    print 'AGG '+str(proto[random.randint(0,1)])+' '+'.'.join(str((ip>>8*i)&255) for i in range(3,-1,-1))+'/24'\
            +' '+str(ps)+'-'+str(random.randint(ps,1<<16))
