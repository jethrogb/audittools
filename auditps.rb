#!/usr/bin/env ruby

require 'etc'

$LOOKUPS=!ARGV.include?("-n")

class EtcLookup
	@@tables={}
	def self.lookup(fun,v)
		return v unless $LOOKUPS
		@@tables[fun]||=[]
		@@tables[fun][v]||=Etc.send(fun,v)[:name]
		@@tables[fun][v]
	end
end

class Array
	def push_if_not_exist(v)
		self.push(v) unless self.include?(v)
	end
end

class Event
	attr_reader :name, :ts, :uids, :gids, :tty, :args
	
	def initialize(name,syscall,*hash)
		hash=hash.first||{}
		@name=name
		@ts=Time.at(syscall[:ts].to_f)
		@uids=[]
		@gids=[]
		@uids.push_if_not_exist EtcLookup.lookup(:getpwuid,syscall[:uid].to_i)
		@uids.push_if_not_exist EtcLookup.lookup(:getpwuid,syscall[:euid].to_i)
		@gids.push_if_not_exist EtcLookup.lookup(:getgrgid,syscall[:gid].to_i)
		@gids.push_if_not_exist EtcLookup.lookup(:getgrgid,syscall[:egid].to_i)
		@tty=syscall[:tty]
		if hash.include? :execve then
			@args=hash[:execve].keys.
			  select { |k| /^a\d+$/=~k.to_s }.
			  sort_by { |k| k.to_s }.
			  map { |k| conv_string(hash[:execve][k]) }
		elsif hash.include? :pid then
			@args=["->",hash[:pid],conv_string(syscall[:comm])]
		else
			@args=[conv_string(syscall[:comm])]
		end
	end
end

$procs=[]

class Ps
	attr_reader :parent, :pid, :events

	def self.pid(pid)
		$procs[pid]||=Ps.new(pid)
	end

	def initialize(pid)
		@pid=pid
		@parent=nil
		@events=[]
	end
	
	def parent=(parent)
		return if @parent
		if parent.is_a? Ps
			@parent=parent
		else
			@parent=Ps.pid(parent)
		end
		@parent.has_child(self)
	end
	
	def has_child(proc)
		@events.push_if_not_exist proc
	end
	
	def has_event(*args)
		@events << Event.new(*args)
	end
end

Syscalls={
	# x86_64
	%w( c000003e  56 ) => :clone,
	%w( c000003e  57 ) => :fork,
	%w( c000003e  58 ) => :vfork,
	%w( c000003e  59 ) => :execve,
	%w( c000003e  60 ) => :exit,
	%w( c000003e 231 ) => :exit_group,

	# x32
	# These are the same as x86_64, except OR'ed with __X32_SYSCALL_BIT 0x40000000
	%w( c000003e 1073741880 ) => :clone,
	%w( c000003e 1073741881 ) => :fork,
	%w( c000003e 1073741882 ) => :vfork,
	%w( c000003e 1073741883 ) => :execve,
	%w( c000003e 1073741884 ) => :exit,
	%w( c000003e 1073742055 ) => :exit_group,

	# i386
	%w( 40000003 120 ) => :clone,
	%w( 40000003   2 ) => :fork,
	%w( 40000003 190 ) => :vfork,
	%w( 40000003  11 ) => :execve,
	%w( 40000003   1 ) => :exit,
	%w( 40000003 252 ) => :exit_group,
}

def lookup_syscall(line)
	Syscalls[[line[:arch],line[:syscall]]]
end

def conv_string(v)
	if v[0..0]=='"' then
		v[1..-2]
	else
		[v].pack("H*").inspect[1..-2].gsub(" ","\\ ").gsub("'","\\'")
	end
end

def parse_line(line)
	/^type=([^ ]+) msg=audit\(([0-9.]+):(\d+)\):*/.match(line)
	rv=/^ +([^= ]+)=([^ ]+)/
	idx=$~[0].length
	ret={:type => $~[1], :ts => $~[2], :event => $~[3]}
	while rv.match(line[idx..-1]) do
		idx+=$~[0].length
		ret[$~[1].to_sym]=$~[2]
	end
	ret
end

def parse_event(event_lines)
	syscall=event_lines.find { |l| l[:type]=="SYSCALL" }
	if syscall then
		pid=syscall[:pid].to_i
		ppid=syscall[:ppid].to_i
		ps=Ps.pid(pid)
		ps.parent=ppid
		if !syscall.include?(:success) or syscall[:success]=="yes" then
			case lookup_syscall(syscall)
				when :execve
					execves=event_lines.select { |l| l[:type]=="EXECVE" }
					if execves and execves.count>0 then
						ps.has_event("EXECVE",syscall,:execve => execves.max_by { |l| l[:argc].to_i })
					end
				when :clone, :fork, :vfork
					cpid=syscall[:exit].to_i
					ps.has_event("CLONE ",syscall,:pid => cpid)
					ch=Ps.pid(cpid)
					ch.parent=pid
				when :exit
					ps.has_event("EXIT  ",syscall)
				when :exit_group
					ps.has_event("EXITGR",syscall)
			end
		end
	end
end

def print_proc(ps,indent="",last=false)
	print " "*(11+1+13+1+13+1+6+3)
	puts indent[0..-2]+"\\_ #{ps.pid}"
	children=ps.events.select { |p| p.is_a? Ps }
	lastps=children.last
	last=false
	ps.events.each do |p|
		last||=(p==lastps)
		if p.is_a? Ps then
			print_proc(p,indent+(last ? "  " : " |"),last)
		else
			print "%-11s %-13s %-13s %-6s   " % [p.ts.strftime('%b%d %H:%M'),p.uids*',',p.gids*',',p.tty]
			puts indent+(children.count==0 || last ? "   " : " | ")+p.name+": "+p.args.join(" ")
		end
	end
end

def print_procs(procs)
	print "%-11s %-13s %-13s %-6s   " % %w( TIME USERS GROUPS TTY )
	puts "PROCESS"
	procs.each { |ps| print_proc(ps) if ps and ps.parent.nil? }
end

event_lines=[]
curev=nil
$stdin.each_line do |line|
	event=parse_line(line.chomp)
	if event[:event]!=curev then
		parse_event(event_lines) unless curev.nil?
		event_lines=[]
		curev=event[:event]
	end
	event_lines << event
end
parse_event(event_lines) unless curev.nil? or event_lines.count==0

print_procs($procs)
