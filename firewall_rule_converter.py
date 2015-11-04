#first step is read the file with all rules and add this rules in a matrix. Every rule is a row of matrix. Every rule have five tag that are: protocol, source port, source ip, destination port and destination ip. Each value of this tag must be specified in a range of value, for example 1-2 , if you want only one value you can repeat value two time, for example the value 1 becomes 1-1.  In the file we have not only rules but have  tag default  it rappresent the action that firewall have to do when the examined packet do not match any rule. ie we can write in iptable DEFAULT = 0 or 1 .Another possible row is ACCEPT O REJECT this mean that the following rules have that action, if you want another action you can write before the rule accept or reject. Every word in iptable are separate with a space. You can read an example in file iptable.py
import sys
import socket, struct
f=open('iptable.py')
tagrules=['protocol = ' ,'srcport = ', 'srcip = ','destport = ', 'destip = '] #strings to search in the rule's line, each rule  have  5 tag
rules = []
action=0                                                                       # variable for identificate the action for each rule
row =0
actions=[]
default_return_value=-1
for line in  f:                                                                # cycle for read one line at time of iptable.py
    if line[0]!= '#':                                                          # if first character of a line is # this means the line is a comment of iptable then we can ignore
        if line == "ACCEPT\n" or line == "accept\n":              # if first word of a line is accept or reject we update the variable action and the rows below that line have this action
            action=1
        elif line == "REJECT\n" or line == "reject\n":
            action =0
        elif line.find("default")!=-1 or line.find("DEFAULT")!=-1:              #default action
            if line.find("ACCEPT")!=-1 or line.find("accept")!=-1:
                default_return_value=1
            elif line.find("REJECT")!=-1 or line.find("REJECT")!=-1:
                default_return_value=0
            else:
                print("default deve valere accept or reject/n")
                sys.exit()
        elif line == "\n":
            continue
        elif line.count('-')!=5:                                                # we check if in this line there are 5 '-', this mean have 5 parameters
            print ("ERROR SYNTAX")
            print("Per mettere un range di valori utilizzare il carattere '-' , ad esempio se una regola accetta protocolli sia tcp che udp si deve inserire 0-1 . Inoltre va messo l'azione della regola prima della regola stessa, si posso raggruppare le regole che hanno la stessa azione. I campi disponibili sono protocol, srcport, srcip, destport, destip. Si devono specificare tutti i campi ecco un esempio \nACCEPT \nprotocol = 1-1 srcport = 500-600  srcip = 4002-5001 destport = 5001-6000 destip = 2002-2002")
            sys.exit()
        else:                                                                  #the row is a rule then we take the parameter of iptable and update the matrix of rules
            rules.append([])                                             # add a vector in the rules
            for i,tag in enumerate(tagrules) :                    # for each element of tagrules search in the row the same string, i is the index and tag is the string in vector tagrules
                index=line.find(tag)                                             # find in the row the element of tagrules, return the position
                if index == -1:                                                # if find function didn't find the string, this means that  iptable not respect the syntax
                    print ("ERROR SYNTAX")
                    print("Per mettere un range di valori utilizzare il carattere '-' , ad esempio se una regola accetta protocolli sia tcp che udp si deve inserire 0-1 . Inoltre va messo l'azione della regola prima della regola stessa, si posso raggruppare le regole che hanno la stessa azione. I campi disponibili sono protocol, srcport, srcip, destport, destip. Si devono specificare tutti i campi ecco un esempio \nACCEPT \nprotocol = 1-1 srcport = 500-600  srcip = 4002-5001 destport = 5001-6000 destip = 2002-2002")
                    sys.exit()
                support_index=line[index:].find ('-')                         #search from index to '-' , This is the end of min value of that x. e.g 5000-...
                if i == 2 or i ==4 :                                            #case we read ip then we translate to integer , 2 is source ip and 4 is destination ip tag
                    ip=line[index+len(tag): support_index+index]
                    packedIP = socket.inet_aton(ip)
                    value_of_rule= struct.unpack("!L", packedIP)[0]
                else :
                    value_of_rule=int(line[index+len(tag): support_index+index]) #the value is not a ip but an integer
                rules[row].append(value_of_rule)                        #append in rules the min value of this tag, the first value of the interval
                support_index=support_index+index+1                             #update index support_index, the support_index focus on the char after the '-' e.g ...-2000
                index=line[support_index:].find(' ')                            #find the space that rappresent the end of  max value and update index
                if index==-1:                                                  #if not find the space this mean that the value is the last value of the row
                    index=line[support_index:].find('\n')
                    if index==-1:
                        print ("ERROR SYNTAX")
                        print("Per mettere un range di valori utilizzare il carattere '-' , ad esempio se una regola accetta protocolli sia tcp che udp si deve inserire 0-1 . Inoltre va messo l'azione della regola prima della regola stessa, si posso raggruppare le regole che hanno la stessa azione. I campi disponibili sono protocol, srcport, srcip, destport, destip. Si devono specificare tutti i campi ecco un esempio \nACCEPT \nprotocol = 1-1 srcport = 500-600  srcip = 4002-5001 destport = 5001-6000 destip = 2002-2002")
                        sys.exit()
                index= index+support_index                                  #is the index of end the value max
                if i == 2 or i ==4 :                        #case we read an ip then we translate to integer , 2 and 4 are index of tagrules to corrispond at  source ip and destination ip
                    ip=line[support_index:index]
                    packedIP = socket.inet_aton(ip)
                    value_of_rule= struct.unpack("!L", packedIP)[0]
                else:
                    value_of_rule =int(line[support_index:index])
                rules[row].append(value_of_rule)        # append in rules the max value of this tag, the second value of the interval
            rules[row].append(action)                                    # append the action of the row, is the last value of the row
            row=row+1                                                          # update row
# matrix rules have all values of iptable.py now.
if default_return_value == -1:
    print("Devi specificare il caso default, che accade se un pacchetto non rientra in nessuna regola! ")
    print("Esempio: DEFAULT = 0")
    sys.exit()
rules.sort()                    # sort the rules

# Write a C function with (lim_sup-lim_inf) conditions that correspond to the
# conditions needed to check a particular group of rules, in particular we have
# a condition for each group in filed. When field is zero we write one rule for
# each group in which the values of "protocol" are divided, same thing for
# "source port" when field is 1, and so on.
# Each condition call a sub function which will check the next field of the
# rules that belong at the same group checked in current condition.
# If we are checking the last field of a rule each conditions returns the action
# chosen for that rule.
# The only function called by programmer is "check()", "check()" will call
# "level_0_X()", "level_0_X()" will call "level_1_X()" and so on untill all
# fiels of a rule are checked or, if some check fail, default action value is
# returned.
#
# @parameter: field, level to be checked, zero for "protocol", one for
#				"source port", and so on;
#
#			  lim_inf and lim_sup, delimit the interval of rule that we have to
#			  	write for level "field" in order to respect the group defined in
#			  	previous fiel of the rules, that is level "field"-1;
#
#			  sublevel_part_name, rappresent the "X" in the name of the
#				functions, such as "level_0_X()", "level_1_X()". Only used to
#				obtain the correct name of the function we want to write now.
def write_function(field, lim_inf, lim_sup, sublevel_part_name):
    global sublevel
        #function name
    if field == 0:
        out_file.write("int check(struct packed_header *pkt) {\n")
    else :
        out_file.write("int level_")
        out_file.write(str(field-1))
        out_file.write("_")
        out_file.write(str(sublevel_part_name))
        out_file.write("(struct packed_header *pkt) {\n")
    # all value rappresented in a 32 bit variable
    #out_file.write("\tuint32_t value=pkt->"+field_name[field]+";\n")
    # or each value in a variable of the same type
    if field == 0:
        out_file.write("\tuint8_t")
    if field == 1 or field == 3:
        out_file.write("\tuint16_t")
    if field == 2 or field == 4:
        out_file.write("\tuint32_t")
    out_file.write(" value=pkt->"+field_name[field]+";\n")
    #function body
    for group_num in range(lim_inf, lim_sup): # [lim_inf, lim_sup)
        out_file.write("\tif (value >= ")
        out_file.write(str(rules[group_indexes[field][group_num]][field*2]))
        out_file.write(" && value <= ")
        out_file.write(str(rules[group_indexes[field][group_num]][field*2+1]))
        out_file.write(")\n")
        if field == len(group_indexes)-1:
            out_file.write("\t\treturn ")
            out_file.write(str(rules[group_indexes[field][group_num]][10]))
            out_file.write(";\n")
        else :
            out_file.write("\t\treturn level_")
            out_file.write(str(field))
            out_file.write("_")
            out_file.write(str(sublevel))
            out_file.write("(pkt);\n")
            sublevel=sublevel+1
    #default return value, if no rule match
    out_file.write("\treturn ")
    out_file.write(str(default_return_value))
    out_file.write(";\n}\n\n");
    #end function


# global value
output_file_name="control.c"
# names that will be used to create a compilable file, according to those used
# in file "packet.h"
field_name=["prot","src_port","src_ip","dest_port","dest_ip"]
# 5 empty array. Each array will contain indexes at which start a new group of
# rules. First array for protocol, second for source port, and so on.
# First group start always at index 0.
group_indexes=[[0],[0],[0],[0],[0]]

# To check correctness of rules we start from first fiel of rules, the protocol,
# that is the first two column of rules. In the first we have the lower limit
# and in the second the upper limit of the value desired for protocol field.
# For each row, starting from the second, we check if the rule is valid for this
# field. If one of the following condition occurr the rule is wrong:
#	1. lim inf of examined rule is different from lim inf of the previous rule
#	   and the lim inf of the examined rule is smaller or equal than the upper lim of the
#	   previous rule;
#	2. lim inf of the examined rule is equal to lim inf of previous rule and the
#	   upper lim of the examined rule differ from the upper lim of the previous
#	   rule.
#
# At the end protocol field is correct and no overlap occurred.
# Now we repeat the same procedure to other field such as source port,source IP,
# and so on. The only care now is to remember that the groups created at each
# step are passed on to successive groups.
for field in range(0, len(rules[0])-1, 2): # 0 2 4 6 8, 10 escluso
    prev_field_group_index=1
    for row in range(1, len(rules)):
    	# if we are testing first field we do not have to remember groups
    	# created for the privious field
        if (field > 0 and prev_field_group_index < len(group_indexes[int((field-2)/2)]) and  group_indexes[int((field-2)/2)][prev_field_group_index] == row):
        	# increment index used to scroll through the groups created for the
        	# previous field
            prev_field_group_index=prev_field_group_index+1
            # insert a new group inherited from the previous field
            group_indexes[int(field/2)].append(row)
        else :
        	# if a rule is in conflict with the previous one
            if ((rules[row][field] != rules[row-1][field]) and (rules[row][field] <= rules[row-1][field+1])) or ((rules[row][field] == rules[row-1][field]) and (rules[row][field+1] != rules[row-1][field+1])):
            	# print an error message and exit
                print ("Error: regole in conflitto!\n")
                exit()
            # if a rule is correct and its range of value, for the field we are
            # examining, rappresent a new group
            if rules[row][field] != rules[row-1][field]:
                #add te index of new rule group
                group_indexes[int(field/2)].append(row)

#print ("Rules correct.\n")

# create the output file
out_file=open(output_file_name, "w")
# header needed to use struct packed_header
out_file.write("#include \"packet.h\"\n\n")
# Now starting from the last field in "rules" we write all the function nedded
# to perform the required checks to match a rule with a packet.
for field_index in range(len(group_indexes)-1, 0, -1):	# for each fiel in rules
    # used in write_function to keep track of the name of subroutine created
    sublevel=1
    # for each group in the next examined field
    for index_group in range(0, len(group_indexes[field_index-1])-1):
    	# write the group of rules for the examined field and group
        write_function(field_index, group_indexes[field_index-1][index_group], group_indexes[field_index-1][index_group+1], index_group+1)
    # write rules for last group
    write_function(field_index, group_indexes[field_index-1][index_group+1], len(rules), index_group+2)
sublevel=1
# write check() function, that will be called to check a packet
write_function(0, 0, len(group_indexes[0]), 1)
out_file.close()	# close output file

print (output_file_name+" creato corretemente.\n")

