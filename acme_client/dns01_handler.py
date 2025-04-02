from dnslib import RR
import dnslib

class DNS01Handler:
     records = {}
     def __init__(self,record):
          self.records = record
     def resolve(self, request, handler):
          if request.q.qtype == 16:
               question = request.q.qname
               question = str(question)
               print("question : ", question)
               parts = question.split('.', 3)
               wildcard_domain = parts[0] + '.*.' + parts[2] +'.'+ parts[3] if parts[3] != '' else parts[0]+ '.*.' + parts[1] +'.'+ parts[2] + '.'
               send = self.records.get(wildcard_domain)
               if not send:
                    reply = request.reply()
                    plz = self.records["TXT"]
                    send = f"_acme-challenge.{question} {plz}"
                    reply.add_answer(*RR.fromZone(send))
                    return reply
               else:
                    reply = request.reply()
                    reply.add_answer(*RR.fromZone(send))
                    return reply
          else:
               question = request.q.qname
               question = str(question)
               reply = request.reply()
               record = self.records["A"]
               reply.add_answer(*RR.fromZone(f"{question} 60 A {record}"))
               return reply