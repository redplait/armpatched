#!perl -w
# script to compare opcodes from adefs.h with binutils/opcodes/aarch64-tbl.h
use strict;
use warnings;

sub parse_adefs
{
  my($fname, $db) = @_;
  my($fh, $str);
  open($fh, '<', $fname) or die("cannot open adefs.h, error $!");
  my $state = 0;
  my $res = 0;
  while( $str = <$fh> )
  {
    chomp $str;
    if ( !$state )
    {
      if ( $str =~ /AD_INSTR_ABS/ )
      { $state = 1; } else { next; }
    }
    last if ( $str eq '};' );
    if ( $str =~ /AD_INSTR_(\S+)/ )
    {
      my $opname = lc($1);
      $opname =~ s/\,$//;
      $db->{$opname}++;
      $res++;
    }
  }
  close $fh;
  return $res;
}

sub parse_bu
{
  my($fname, $db) = @_;
  my($str, $fh);
  open($fh, '<', $fname) or die("cannot open aarch64-tbl.h, error $!");
  while( $str = <$fh> )
  {
    chomp $str;
    next if ( $str !~ /INSN\s*\(\s*\"([^\"]+)\"/ );
    my $opname = lc($1);
    if ( ! exists $db->{$opname} )
    {
      printf("%s\n", $opname);
    }
  }
  close $fh;
}

# main
die("adefs.h aarch64-tbl.h") if ( $#ARGV != 1 );
my %ops;
parse_adefs($ARGV[0], \%ops);
parse_bu($ARGV[1], \%ops);
