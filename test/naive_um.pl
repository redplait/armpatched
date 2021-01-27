#!perl -w
# script to measure how many symbols can be found with current auto builded state machine using load_config
# 19 Jan 2021 (C) RedPlait
use strict;
use warnings;

my $prg = "D:/src/armpatched/Release/ldr.exe -rd -c 40 -lc ";
my @sections;
my %gexp;
my $tcount = 8;

# fill exported from $prg -de
sub read_exports
{
  my $fname = shift;
  my($fh, $str);
  open($fh, $prg . "-de " . $fname . "|") or die("cannot run $prg -de $fname, error $!\n");
  while($str = <$fh>)
  {
    chomp $str;
    next if ( $str !~ /Ord \d+ \d ([0-9a-f]+)/i );
    my $rva = hex($1);
    next if ( !$rva );
    $gexp{$rva} = 1;
  }
  close $fh;
}

# fill @sections from $prg -ds
sub read_sections
{
  my $fname = shift;
  my($fh, $str, $status);
  open($fh, $prg . "-ds " . $fname . "|") or die("cannot run $prg -ds $fname, error $!\n");
  $status = 0;
  while($str = <$fh>)
  {
    chomp $str;
    if ( $str =~ /\] (\S+): VA (\w+), VSize (\w+)/ )
    {
      $status = 1;
      # we interested only in some sections
      if ( $1 eq '.data' ||
           $1 eq 'mrdata'  # in ntdll.dll
         )
      {
        # name, va, size
        push(@sections, [ $1, hex($2), hex($3), 0, 0 ]);
      }
      next;
    }
    last if ( $status ); 
  }
  close $fh;
}

sub check_addr
{
  my $arg = shift;
  my $rva = shift;
  my($fh, $str, $cmd);
  if ( $tcount )
  {
    $cmd = sprintf("-t %d -der %s %X", $tcount, $arg, $rva);
  } else {
    $cmd = sprintf("-der %s %X", $arg, $rva);
  }
  open($fh, $prg . $cmd . "|") or die("cannot run $prg $cmd, error $!\n");
  while($str = <$fh>)
  {
    chomp $str;
    if ( $str =~ /^CANBEFOUND/ )
    {
      close $fh;
      return 1;
    }
  }
  close $fh;
  return 0;
}

sub in_our_section
{
  my $rva = shift;
  foreach my $s ( @sections )
  {
    return $s if ( ($rva >= $s->[1]) && ($rva < ($s->[1] + $s->[2])) );
  }
  return undef;
}

sub dump_stat
{
  my $total = 0;
  my $found = 0;
  my $s;
  foreach my $s ( @sections )
  {
    $total += $s->[3];
    $found += $s->[4];
  }
  printf("total: %d symbols, found %d\n", $total, $found);
}

sub read_pdmp
{
  my $fname = shift;
  my $arg = shift;
  my($fh, $rva, $name, $s, $str);
  open($fh, '<', $fname) or die("cannot open file $fname, error $!\n");
  while($str = <$fh>)
  {
    chomp $str;
    next if ( $str !~ m|^// pubsym <rva (\w+)> (.*)$| );
    $rva = hex($1);
    $str = $2;
    # check if this symbol already exported
    next if ( exists $gexp{$rva} );
    # we need only data
    next if ( $str =~ /<code>/ );
    next if ( $str =~ /__imp_/ );
    next if ( $str =~ /\?\?_C@/ );
    $s = in_our_section($rva);
    next if ( !defined($s) );
    $s->[3]++;
    $s->[4] += check_addr($arg, $rva);
  }
  close $fh;
}

# main
if ( $#ARGV != 1 )
{
  printf("Usage: .exe .pdmp (argv size %d)\n", $#ARGV);
  exit(6);
}

read_sections($ARGV[0]);
read_exports($ARGV[0]);
read_pdmp($ARGV[1], $ARGV[0]);
dump_stat();