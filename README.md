# SMF Bot Hygiene

## Overview:
This is our sample robots.txt file, and the portion of .htaccess that we use to restrict access to bots.

Everybody's site is a bit different; we are offering these as starter packs for folks running SMF sites.  

## robots.txt Notes & Criteria:
* Robots.txt is voluntary; only "good" crawlers adhere to it.  It is still immensely helpful, though, because there are lots of links crawlers shouldn't attempt to load.  Robots.txt can thus drastically reduce unnecessary site hits for the "good" bots.  
* Our site does not allow guests to see attachments, so they are restricted here.
* We restrict msg level queries here.  This is actually kinda important, as msg links load the whole page of the topic the msg is on.  So, if a page of a topic has 30 msgs on it, the crawler will otherwise load that same page 30 times as it follows each link on the page, which is extremely wasteful.  Note this has proven to drastically reduce Google site requests.
* End user functions are restricted, e.g., profile & notification activity, posts, modifications, likes, etc.  There is no reason for crawlers to attempt any of these, so let them know.
* Admin functions are restricted.
* Search functions are restricted.  They should get that info off of the topics themselves.
* Yes, I know Google does not honor crawl-delay, but I can hope.

## .htaccess Notes & Criteria:
* Our site attempts to allow true search engine crawlers that honor robots.txt.  Even international crawlers, as we support folks from all over the world.
* Crawlers that are not for search engines will get blocked, e.g., AI crawlers are blocked.  Social media crawlers are blocked, e.g., Facebook, TikTok, etc.  
* Crawlers that try to remain anonymous, e.g., by disguising the user agent, are blocked.
* Crawlers that do not honor robots.txt are blocked.
* We also now block when we see old browser versions in the useragent, as this appears to be 100% bot activity - Chrome < 80.0, Firefox < 100.0 & Opera < 10.0.
* To constuct this list, we started with the useragent list from this site: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/_generator_lists/bad-user-agents.list
* We removed some valid international crawlers from that list, and have added many new ones, primarily social media sites & AI bots.  
* We also attempt to restrict IP ranges known for malicious activity or aggressive crawling.
* We ensure none of our users are in those IP ranges first...
* Since we have a fair amount of international users, we attempt to avoid blocking by country.  We do, however, now block China.

## htaccess_asn_list.txt:
* This file holds the list of ASNs that are blocked in the .htaccess file.
* These ASNs have been problematic, one way or another.  Attacks come from these ASNs.  Either they have been exploited by botnets, or, they simply do not monitor such activity coming from their networks.

## cidr_list_cleaner.php:
* The CIDR list you get from an ASN lookup is EXTREMELY inefficient.  Most IP ranges are duplicated or overlap.  Also, many CIDRs are consecutive, and the list can often be simplified by combining them.
* This utility cleans up all duplication & overlap & combines adjacent CIDRs where possible, typically resulting in a 98-99% reduction in list size.
* It can be run from either the command line or a browser.  It accepts a user-specified flat file with a list of valid CIDRs, one per line; output is written to a new file.  Entries that don't match a CIDR format are dropped with an error message.
* There is no limit to the number of records in the flat file.
* It works for both ipv4 & ipv6.
