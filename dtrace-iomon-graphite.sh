#!/usr/bin/env bash

TICKS=1
RUNTIME=-1
[ -n "$1" ] && TICKS=$1
[ -n "$2" ] && RUNTIME=$2

if [ 1 == 1 ]; then
/usr/sbin/dtrace -v -C -s /dev/stdin << EOF
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=16m

#include <sys/file.h>

inline int    TICKS=$TICKS;
inline int    RUNTIME=$RUNTIME;
inline string ADDR=\$\$3;

dtrace:::BEGIN
{
       TIMER = ( TICKS != NULL ) ?  TICKS : 1 ;
       ticks = TIMER;
       TITLE=10;
       timerun=0;
       title = 0;

       /* www.dtracebook.com/index.php/Application_Level_Protocols:nfsv3syncwrite.d */
       stable_how[0] = "Unstable";
       stable_how[1] = "Data_Sync";
       stable_how[2] = "File_Sync";
       /* See /usr/include/nfs/nfs.h */
}


/* ===================== beg TCP =================================
tcp:::send / ( ADDR == NULL || args[3]->tcps_raddr == ADDR ) &&  args[2]->ip_plength - args[4]->tcp_offset > 0 /
{      this->type="R";
       @tcp_ct[this->type]=count();
       @tcp_sz[this->type]=sum(args[2]->ip_plength - args[4]->tcp_offset);
       @tcp_tm[this->type]=max(0);
}
tcp:::receive / (ADDR==NULL || args[3]->tcps_raddr==ADDR ) && args[2]->ip_plength-args[4]->tcp_offset > 0 /
{      this->type="W";
       @tcp_ct[this->type]=count();
       @tcp_sz[this->type]=sum( args[2]->ip_plength - args[4]->tcp_offset);
       @tcp_tm[this->type]=max(0);
}  ===================== end TCP ================================= */


/* ===================== beg NFS ================================= */


nfsv3:::op-read-start, nfsv3:::op-write-start ,nfsv4:::op-read-start {
        tm[args[0]->ci_remote,args[1]->noi_xid] = timestamp;
        sz[args[0]->ci_remote,args[1]->noi_xid] = args[2]->count    ;
        flag[args[0]->ci_remote,args[1]->noi_xid] = 0;
}
nfsv3:::op-write-start {
        flag[args[0]->ci_remote,args[1]->noi_xid] = args[2]->stable;
}
nfsv4:::op-write-start {
        flag[args[0]->ci_remote,args[1]->noi_xid] = args[2]->stable;
        tm[args[0]->ci_remote,args[1]->noi_xid] = timestamp;
        sz[args[0]->ci_remote,args[1]->noi_xid] = args[2]->data_len ;
}

nfsv3:::op-read-done, nfsv3:::op-write-done, nfsv4:::op-read-done, nfsv4:::op-write-done
/tm[args[0]->ci_remote,args[1]->noi_xid]/
{
        this->delta= (timestamp - tm[args[0]->ci_remote,args[1]->noi_xid])/1000;
        this->type =  probename == "op-write-done" ? "W" : "R";
        this->flag =  flag[args[0]->ci_remote,args[1]->noi_xid];

    /* ipaddr=ip[args[1]->noi_xid]; */
        /*
        this->file =  args[1]->noi_curpath;
        this->ipaddr = inet_ntoa(&((struct sockaddr_in *)((struct svc_req *)arg0)->
            rq_xprt->xp_xpc.xpc_rtaddr.buf)->sin_addr.S_un.S_addr);
        this->port = ((struct sockaddr_in *)((struct svc_req *)arg0)->
            rq_xprt->xp_xpc.xpc_rtaddr.buf)->sin_port;

        @nfs_fir["R",this->file,this->ipaddr,this->port]= sum( (this->type == "R" ? sz[args[0]->ci_remote,args[1]->noi_xid] : 0));
        @nfs_fiw["W",this->file,this->ipaddr,this->port]= sum( (this->type == "W" ? sz[args[0]->ci_remote,args[1]->noi_xid] : 0));
       */

        /* store size along with max time so the can be correlated */
        this->overload = ( (this->delta) * (1000*1000*1000) +   sz[args[0]->ci_remote,args[1]->noi_xid]);
        @nfs_mx[this->flag,"R"]=max( (this->type == "R" ? this->overload : 0));
        @nfs_mx[this->flag,"W"]=max( (this->type == "W" ? this->overload : 0));
        @nfs_tm[this->flag,this->type]=sum(this->delta);
        @nfs_ct[this->flag,this->type]=count();
        @nfs_sz[this->flag,this->type]=sum(sz[args[0]->ci_remote,args[1]->noi_xid]);

        tm[args[0]->ci_remote,args[1]->noi_xid] = 0;
        sz[args[0]->ci_remote,args[1]->noi_xid] = 0;
        flag[args[0]->ci_remote,args[1]->noi_xid]=0;
}

/*

nfsv3:::op-read-start, nfsv3:::op-write-start ,nfsv4:::op-read-start {
        tm[args[1]->noi_xid] = timestamp;
        sz[args[1]->noi_xid] = args[2]->count    ;
}
nfsv4:::op-write-start {
        tm[args[1]->noi_xid] = timestamp;
        sz[args[1]->noi_xid] = args[2]->data_len ;
}

nfsv3:::op-read-done, nfsv3:::op-write-done, nfsv4:::op-read-done, nfsv4:::op-write-done
/tm[args[1]->noi_xid]/
{
        this->delta= (timestamp - tm[args[1]->noi_xid]);
        this->type =  probename == "op-write-done" ? "W" : "R";
        @nfs_tm[this->type]=sum(this->delta);
        @nfs_mx["R"]=max( (this->type == "R" ? this->delta : 0));
        @nfs_mx["W"]=max( (this->type == "W" ? this->delta : 0));
        @nfs_ct[this->type]=count();
        @nfs_sz[this->type]=sum(sz[args[1]->noi_xid]);
        tm[args[1]->noi_xid] = 0;
        sz[args[1]->noi_xid] = 0;
}
*/
 /* --------------------- end NFS --------------------------------- */


/* ===================== beg ZFS ================================= */

zfs_read:entry,zfs_write:entry {
         self->ts = timestamp;
         self->filepath = args[0]->v_path;
         self->size = ((uio_t *)arg1)->uio_resid;
}
zfs_read:entry  { self->flag=0; }
zfs_write:entry { self->flag = args[2] & (FRSYNC | FSYNC | FDSYNC) ? 1 : 0; }
zfs_read:return,zfs_write:return /self->ts / {
        this->type =  probefunc == "zfs_write" ? "W" : "R";
        this->delta=(timestamp - self->ts) /1000;

        @zfs_tm[self->flag,this->type]= sum(this->delta);
        @zfs_ct[self->flag,this->type]= count();
        @zfs_sz[self->flag,this->type]= sum(self->size);
        /*      convert time from ns to us , */
        this->overload = ( (this->delta) * (1000*1000*1000) + self -> size );
        @zfs_mx[self->flag,"R"]=max( (this->type == "R" ? this->overload : 0));
        @zfs_mx[self->flag,"W"]=max( (this->type == "W" ? this->overload : 0));

        /*@zfs_hist["hist_name,",this->type,self->flag]=quantize(this->delta);*/

        self->flags=0;
        self->ts=0;
        self->filepath=0;
        self->size=0;
}

/*
zfs_read:entry,zfs_write:entry {
         self->ts = timestamp;
         self->filepath = args[0]->v_path;
         self->size = ((uio_t *)arg1)->uio_resid;
}
zfs_read:return,zfs_write:return /self->ts  / {
        this->fn= "";
        this->type =  probefunc == "zfs_write" ? "W" : "R";
        this->delta=(timestamp - self->ts) ;
        @zfs_tm[this->type]= sum(this->delta);
        @zfs_ct[this->type]=count();
        @zfs_sz[this->type]=sum(self->size);
        @zfs_mx["R"]=max( (this->type == "R" ? this->delta : 0));
        @zfs_mx["W"]=max( (this->type == "W" ? this->delta : 0));
        self->ts=0;
        self->filepath=0;
        self->size=0;
} */

 /* --------------------- end ZFS --------------------------------- */


/* ===================== beg IO ================================= */
io:::start / arg0 != NULL && args[0]->b_addr != 0 / {
       tm_io[args[0]->b_edev, args[0]->b_blkno] = timestamp;
       sz_io[args[0]->b_edev, args[0]->b_blkno] = args[0]->b_bcount;
}

io:::done /tm_io[args[0]->b_edev, args[0]->b_blkno] /
{

       this->type = args[0]->b_flags & B_READ ? "R" : "W" ;
       this->delta = (( timestamp - tm_io[ args[0]->b_edev, args[0]->b_blkno] ))/1000;
       this->size =sz_io[ args[0]->b_edev, args[0]->b_blkno ] ;
       @io_tm[this->type]=sum(this->delta);
       @io_ct[this->type]=count();
       @io_sz[this->type]=sum(this->size) ;

       this->overload = ( (this->delta) * (1000*1000*1000) + this->size );
       @io_mx["R"]=max( (this->type == "R" ? this->overload : 0));
       @io_mx["W"]=max( (this->type == "W" ? this->overload : 0));

       tm_io[args[0]->b_edev, args[0]->b_blkno] = 0;
       sz_io[args[0]->b_edev, args[0]->b_blkno] = 0;

       /*@io_hist["hist_name,",this->type]=quantize(this->delta);*/
}

/*
io:::start / arg0 != NULL && args[0]->b_addr != 0 / {
       tm_io[(struct buf *)arg0] = timestamp;
       sz_io[(struct buf *)arg0] = args[0]->b_bcount;
}
io:::done /tm_io[(struct buf *)arg0]/ {
      this->type = args[0]->b_flags & B_READ ? "R" : "W" ;
      this->delta = (( timestamp - tm_io[(struct buf *)arg0]));
       @io_tm[this->type]=sum(this->delta);
       @io_mx["R"]=max( (this->type == "R" ? this->delta : 0));
       @io_mx["W"]=max( (this->type == "W" ? this->delta : 0));
       @io_ct[this->type]=count();
       @io_sz[this->type]=sum(sz_io[(struct buf *)arg0]) ;
       sz_io[(struct buf *)arg0] = 0;
       tm_io[(struct buf *)arg0] = 0;
}*/ /* --------------------- end IO --------------------------------- */



profile:::tick-1sec / ticks > 0 / { ticks--; timerun++; }
profile:::tick-1sec / timerun > RUNTIME && RUNTIME != -1  / { exit(0); }

profile:::tick-1sec
/ ticks == 0 /
{

/*
       normalize(@nfs_tm,TIMER);
       normalize(@nfs_mx,TIMER);
       normalize(@nfs_ct,TIMER);
       normalize(@nfs_sz,TIMER);

       normalize(@io_tm,TIMER);
       normalize(@io_mx,TIMER);
       normalize(@io_ct,TIMER);
       normalize(@io_sz,TIMER);

       normalize(@zfs_tm,TIMER);
       normalize(@zfs_ct,TIMER);
       normalize(@zfs_sz,TIMER);
       normalize(@zfs_mx,TIMER);

       printa("nfs_tm ,%s,%@d\n",@nfs_tm);

       printa("nfs_tm ,%s,%@d\n",@nfs_tm);
       printa("nfs_mx ,%s,%@d\n",@nfs_mx);
       printa("nfs_ct ,%s,%@d\n",@nfs_ct);
       printa("nfs_sz ,%s,%@d\n",@nfs_sz);

       printa("io_tm  ,%s,%@d\n",@io_tm);
       printa("io_mx  ,%s,%@d\n",@io_mx);
       printa("io_ct  ,%s,%@d\n",@io_ct);
       printa("io_sz  ,%s,%@d\n",@io_sz);

       printa("zfs_tm ,%s,%@d\n",@zfs_tm);
       printa("zfs_ct ,%s,%@d\n",@zfs_ct);
       printa("zfs_sz ,%s,%@d\n",@zfs_sz);
       printa("zfs_mx ,%s,%@d\n",@zfs_mx);
*/

       normalize(@nfs_tm,TIMER);
       printa("nfs%d_tm ,%s,%@d\n",@nfs_tm);
       printa("nfs%d_mx ,%s,%@d\n",@nfs_mx);
       normalize(@nfs_ct,TIMER);
       printa("nfs%d_ct ,%s,%@d\n",@nfs_ct);
       normalize(@nfs_sz,TIMER);
       printa("nfs%d_sz ,%s,%@d\n",@nfs_sz);

      /* trunc(@nfs_fiw,5);
       normalize(@nfs_fiw,TIMER);
       printa("nfs_fiw ,%s,%s=%s=%d,%@d\n",@nfs_fiw);
       trunc(@nfs_fiw);
       trunc(@nfs_fir,5);
       normalize(@nfs_fir,TIMER);
       printa("nfs_fir ,%s,%s=%s=%d,%@d\n",@nfs_fir);
       trunc(@nfs_fir);
      */
       normalize(@io_tm,TIMER);
       printa("io_tm  ,%s,%@d\n",@io_tm);
       printa("io_mx  ,%s,%@d\n",@io_mx);
       normalize(@io_ct,TIMER);
       printa("io_ct  ,%s,%@d\n",@io_ct);
       normalize(@io_sz,TIMER);
       printa("io_sz  ,%s,%@d\n",@io_sz);

       normalize(@zfs_tm,TIMER);
       printa("zfs%d_tm ,%s,  %@d\n",@zfs_tm);
       printa("zfs%d_mx ,%s,  %@d\n",@zfs_mx);
       normalize(@zfs_ct,TIMER);
       printa("zfs%d_ct ,%s,  %@d\n",@zfs_ct);
       normalize(@zfs_sz,TIMER);
       printa("zfs%d_sz ,%s,  %@d\n",@zfs_sz);

       /*
       # if arrays are not "trunc"-ed then normalize
       # only works the first time ?!
       # change clear(@nfs_sz) to trunc(@nfs_sz)
       printf("normalize nfs_sz by %d\n", TIMER);
       */
       normalize(@nfs_sz,TIMER);
       normalize(@zfs_sz,TIMER);
       normalize(@io_sz,TIMER);

       printa("nfs%d_szps  ,%s,%@d\n",@nfs_sz);
       printa("io_szps  ,%s,%@d\n",@io_sz);
       printa("zfs%d_szps  ,%s,%@d\n",@zfs_sz);

       /*
       # file bytes written should be normalized
       */

	/*
       normalize(@nfs_avtmsz,TIMER);
       normalize(@nfs_cttmsz,TIMER);
       printa("%s,%s,%@d,%d\n",@nfs_avtmsz);
       printa("%s,%s,%@d,%d\n",@nfs_cttmsz);
       trunc(@nfs_avtmsz);
       trunc(@nfs_cttmsz);
       */

/*
       normalize(@tcp_ct,TIMER);
       normalize(@tcp_sz,TIMER);

       printa("tcp_ct ,%s,%@d\n",@tcp_ct);
       printa("tcp_sz ,%s,%@d\n",@tcp_sz);

       clear(@tcp_ct);
       clear(@tcp_sz);
*/

       clear(@nfs_tm);
       clear(@nfs_ct);
       clear(@nfs_sz);

       clear(@io_tm);
       clear(@io_ct);
       clear(@io_sz);

       clear(@zfs_tm);
       clear(@zfs_ct);
       clear(@zfs_sz);

       clear(@io_mx);
       clear(@nfs_mx);
       clear(@zfs_mx);


}

profile:::tick-1sec
/ ticks == 0 /
{
       ticks= TIMER;
       printf("!\n");
}

/* use if you want to print something every TITLE lines */
profile:::tick-1sec / title <= 0 / { title=TITLE; }
EOF
# Start perl
#
fi| perl -e '
use Sun::Solaris::Kstat;
use IO::Socket;

$| = 1;
my $prefix = "";
my $time = 0;
my $HOSTNAME = `hostname`;
chomp($HOSTNAME);

my $last_arcHits = 0;
my $last_arcMisses = 0;

my $graphite_host = "graphite.cs.avira.com";
my $graphite_port = 2003;

my $sock = NULL;

sub connectGraphite() {
  $sock = IO::Socket::INET->new(
    Proto    => 'tcp',
    PeerPort => $graphite_port,
    PeerAddr => $graphite_host,
  ) or die "Could not create socket: $!\n";
}

sub writeMetric {
  my $msg = $_[0];
  print $msg;
  if ($sock) {
    $sock->send($msg);
  }
}

sub showKstat() {
  my $Kstat = Sun::Solaris::Kstat->new();
  $prefix = "cloud.storage." . $HOSTNAME . ".mem";
  ### System Memory ###
  my $phys_pages = ${Kstat}->{unix}->{0}->{system_pages}->{physmem};
  my $free_pages = ${Kstat}->{unix}->{0}->{system_pages}->{freemem};
  my $lotsfree_pages = ${Kstat}->{unix}->{0}->{system_pages}->{lotsfree};
  my $pagesize = `pagesize`;

  my $phys_memory = ($phys_pages * $pagesize);
  my $free_memory = ($free_pages * $pagesize);
  my $lotsfree_memory = ($lotsfree_pages * $pagesize);

  writeMetric(sprintf("%s.physical %s %s\n", $prefix, $phys_memory, $time));
  writeMetric(sprintf("%s.free %s %s\n", $prefix, $free_memory, $time));
  writeMetric(sprintf("%s.lotsfree %s %s\n", $prefix, $lotsfree_memory, $time));

  ## ARC Sizing
  #### ARC Sizing ###############
  my $mru_size = ${Kstat}->{zfs}->{0}->{arcstats}->{p};
  my $target_size = ${Kstat}->{zfs}->{0}->{arcstats}->{c};
  my $arc_min_size = ${Kstat}->{zfs}->{0}->{arcstats}->{c_min};
  my $arc_max_size = ${Kstat}->{zfs}->{0}->{arcstats}->{c_max};

  my $arc_size = ${Kstat}->{zfs}->{0}->{arcstats}->{size};
  my $mfu_size = ${target_size} - $mru_size;
  my $mru_perc = 100*($mru_size / $target_size);
  my $mfu_perc = 100*($mfu_size / $target_size);
  #$time = time();

  $prefix = "cloud.storage." . $HOSTNAME . ".arc";

  writeMetric(sprintf("%s.current_size %s %s\n", $prefix, $arc_size/1024/1024, $time));
  writeMetric(sprintf("%s.target_size %s %s\n", $prefix, $target_size/1024/1024, $time));
  writeMetric(sprintf("%s.min %s %s\n", $prefix, $arc_min_size/1024/1024, $time));
  writeMetric(sprintf("%s.max %s %s\n", $prefix, $arc_max_size/1024/1024, $time));

  writeMetric(sprintf("%s.mru_perc %s %s\n", $prefix, $mru_perc, $time));
  writeMetric(sprintf("%s.mru_size %s %s\n", $prefix, $mru_size/1024/1024, $time));
  writeMetric(sprintf("%s.mfu_perc %s %s\n", $prefix, $mfu_perc, $time));
  writeMetric(sprintf("%s.mfu_size %s %s\n", $prefix, $mfu_size/1024/1024, $time));

  my $arcHits = ${Kstat}->{zfs}->{0}->{arcstats}->{hits};
  my $arcMisses = ${Kstat}->{zfs}->{0}->{arcstats}->{misses};
  $time = time();

  $interval = $ARGV[0] || 1;
  unless ($last_arcHits == 0) {
    my $hps = ($arcHits - $last_arcHits) / $interval;
    my $mps = ($arcMisses - $last_arcMisses) / $interval;
    writeMetric(sprintf("%s.arc_count_hits %s %s\n%s.arc_count_misses %s %s\n", $prefix, $hps, $time, $prefix, $mps, $time));
  }

  writeMetric(sprintf("%s.arc_perc_hits %.2f %s\n", $prefix, ($arcHits/($arcHits+$arcMisses))*100, $time));
  writeMetric(sprintf("%s.arc_perc_misses %.2f %s\n", $prefix, ($arcMisses/($arcHits+$arcMisses))*100, $time));

  $last_arcHits   = $arcHits; 
  $last_arcMisses = $arcMisses;

  ${Kstat}->update();
}

while (my $line = <STDIN>) {
       $line=~ s/\s+//g;
       if ( $line eq "!"  ) {
          connectGraphite();
          $time = time();
          $IOPS=$io_ct{"R"} + $io_ct{"W"};

          foreach $r_w ("R","W") {
           # zfs1 is zfs sync writes (also set for reads but not used)
           # zfs0 is no-sync zfs writes
            foreach $io_type ("io","zfs1","zfs0","nfs0", "nfs1","nfs2") {
              # ct = count, sz = sum of bytes over period, tm = sum of time for all ops
              if ( $r_w eq "R" && $io_type eq "nfs1" ) { next; }
              if ( $r_w eq "R" && $io_type eq "nfs2" ) { next; }

              foreach $var_type ("ct","sz","tm", "szps") {
                # if using cumulative values get old and do diff
                #       nfs               ct                  R
                $cur=${$io_type . "_" .  $var_type         }{$r_w}||0;
                ${$var_type}=$cur;
              }
              $mx=${$io_type . "_mx"}{$r_w}||0 ;
              $avg_sz_kb=0;
              $ms=0;
              $ms_8kb=0;
              $mx_sz=0;
              $mx_ms=0;
              if ( $ct > 0 ) {
                  $ms=(($tm/1000000)/$ct);
                  $avg_sz_kb=($sz/$ct)/1024;
              }
              if ( $sz > 0 ) {
                  $ms_8kb=(($tm/1000000)/($sz/(8*1024)));
              }

              # mx_ms is overloaded with the max time and the size for that max time
              # time is in the upper half and size in the lower
              $mx_ms=$mx/1000000;
              $mx_ms=(int($mx/  (1000*1000*1000) )/1000);
              $mx_sz=(   ($mx % (1000*1000*1000) )/1024);
              #clear out the make value
              ${$io_type . "_mx"}{$r_w}=0;

              # sz is already normalized in the dtrace script to per second
              $sz_MB=$sz/(1024*1024);
              $io_name=$io_type;

              #  NFS flags
              #  stable_how[0] = "Unstable";
              #  stable_how[1] = "Data_Sync";
              #  stable_how[2] = "File_Sync";
 
              if ( $io_name eq "nfs0"  ) { $io_name="nfs" }
              if ( $io_name eq "nfs1"  ) { $io_name="nfssyncD" }
              if ( $io_name eq "nfs2"  ) { $io_name="nfssyncF" }
              if ( $io_name eq "zfs1" && $r_w eq "R"  ) { next }
              if ( $io_name eq "zfs1"  ) { $io_name="zfssync" }
              if ( $io_name eq "zfs0"  ) { $io_name="zfs" }

	      $prefix = "cloud.storage." . $HOSTNAME . ".fs." . $io_name . "." . $r_w;

              writeMetric(sprintf("%s.ms_8kb %s %s\n", $prefix, $ms_8kb, $time));
              writeMetric(sprintf("%s.sz_MB %s %s\n",$prefix, $sz_MB, $time));
              writeMetric(sprintf("%s.avg_sz_kb %s %s\n",$prefix, $avg_sz_kb, $time));
              writeMetric(sprintf("%s.ms %s %s\n",$prefix, $ms, $time));
              writeMetric(sprintf("%s.mx_ms %s %s\n",$prefix, $mx_ms, $time));
              writeMetric(sprintf("%s.count %s %s\n",$prefix, $ct, $time));

              foreach $var_type ("ct","sz","tm","szps") {
                 ${$io_type . "_" .  $var_type         }{$r_w}=0;
              }

              $mx=${$io_type . "_mx"}{$r_w}||0 ;

           }
         }

	 $prefix = "cloud.storage." . $HOSTNAME . ".fs";
         writeMetric(sprintf("%s.iops %s %s\n",$prefix, $IOPS, $time));

         showKstat();

         # zero out all previous values
         # the histograms get deleted in the loops above
         foreach $r_w ("R","W") {
           foreach $io_type ("io","zfs1","zfs0","nfs") {
             foreach $var_type ("ct","sz","tm","szps") {
                ${$io_type . "_" .  $var_type }{$r_w}=0;
             }
           }
         }
	$sock->shutdown(0);
       } else {
          ($area, $r_w, $value)=split(",",$line);
          ${$area}{$r_w}=$value;
       }
}' $TICKS
