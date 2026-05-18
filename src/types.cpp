// ============================================================================
// types.cpp — AppType string conversion + SNI-to-app classification
// NetScope DPI Lite
//
// sniToAppType() is reused almost entirely from the original repository's
// types.cpp, which had the most complete CDN alias mapping. Extended with
// namespace change and FlowAction support.
// ============================================================================

#include "types.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace NetScope {

// ----------------------------------------------------------------------------
// FiveTuple::toString
// ----------------------------------------------------------------------------
std::string FiveTuple::toString() const {
    auto formatIP = [](uint32_t ip) -> std::string {
        std::ostringstream s;
        s << ((ip >>  0) & 0xFF) << '.'
          << ((ip >>  8) & 0xFF) << '.'
          << ((ip >> 16) & 0xFF) << '.'
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    std::ostringstream ss;
    ss << formatIP(src_ip) << ':' << src_port
       << " -> "
       << formatIP(dst_ip) << ':' << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ')';
    return ss.str();
}

// ----------------------------------------------------------------------------
// appTypeToString
// ----------------------------------------------------------------------------
std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// ----------------------------------------------------------------------------
// sniToAppType — maps SNI hostname / HTTP Host to AppType
//
// Uses lowercase substring matching + CDN alias coverage.
// Order matters: YouTube before Google (ytimg check).
// Reused from original repo's types.cpp with full CDN alias set.
// ----------------------------------------------------------------------------
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    std::string s = sni;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    // YouTube (check before Google — ytimg alias)
    if (s.find("youtube") != std::string::npos ||
        s.find("ytimg")   != std::string::npos ||
        s.find("youtu.be")!= std::string::npos)
        return AppType::YOUTUBE;

    // Google (after YouTube to avoid ytimg→GOOGLE mismatch)
    if (s.find("google")     != std::string::npos ||
        s.find("gstatic")    != std::string::npos ||
        s.find("googleapis") != std::string::npos ||
        s.find("gvt1")       != std::string::npos)
        return AppType::GOOGLE;

    // Facebook / Meta CDNs
    if (s.find("facebook")  != std::string::npos ||
        s.find("fbcdn")     != std::string::npos ||
        s.find("fb.com")    != std::string::npos ||
        s.find("fbsbx")     != std::string::npos ||
        s.find("meta.com")  != std::string::npos)
        return AppType::FACEBOOK;

    // Instagram (Meta-owned)
    if (s.find("instagram")    != std::string::npos ||
        s.find("cdninstagram") != std::string::npos)
        return AppType::INSTAGRAM;

    // WhatsApp (Meta-owned)
    if (s.find("whatsapp") != std::string::npos ||
        s.find("wa.me")    != std::string::npos)
        return AppType::WHATSAPP;

    // Twitter / X
    if (s.find("twitter") != std::string::npos ||
        s.find("twimg")   != std::string::npos ||
        s.find("x.com")   != std::string::npos ||
        s.find("t.co")    != std::string::npos)
        return AppType::TWITTER;

    // Netflix + CDN
    if (s.find("netflix")   != std::string::npos ||
        s.find("nflxvideo") != std::string::npos ||
        s.find("nflximg")   != std::string::npos)
        return AppType::NETFLIX;

    // Amazon AWS / CloudFront
    if (s.find("amazon")     != std::string::npos ||
        s.find("amazonaws")  != std::string::npos ||
        s.find("cloudfront") != std::string::npos ||
        s.find("aws")        != std::string::npos)
        return AppType::AMAZON;

    // Microsoft / Azure / Office365
    if (s.find("microsoft") != std::string::npos ||
        s.find("msn.com")   != std::string::npos ||
        s.find("office")    != std::string::npos ||
        s.find("azure")     != std::string::npos ||
        s.find("live.com")  != std::string::npos ||
        s.find("outlook")   != std::string::npos ||
        s.find("bing")      != std::string::npos)
        return AppType::MICROSOFT;

    // Apple / iCloud
    if (s.find("apple")    != std::string::npos ||
        s.find("icloud")   != std::string::npos ||
        s.find("mzstatic") != std::string::npos ||
        s.find("itunes")   != std::string::npos)
        return AppType::APPLE;

    // Telegram
    if (s.find("telegram") != std::string::npos ||
        s.find("t.me")     != std::string::npos)
        return AppType::TELEGRAM;

    // TikTok / ByteDance
    if (s.find("tiktok")    != std::string::npos ||
        s.find("tiktokcdn") != std::string::npos ||
        s.find("musical.ly")!= std::string::npos ||
        s.find("bytedance") != std::string::npos)
        return AppType::TIKTOK;

    // Spotify
    if (s.find("spotify")  != std::string::npos ||
        s.find("scdn.co")  != std::string::npos)
        return AppType::SPOTIFY;

    // Zoom
    if (s.find("zoom") != std::string::npos)
        return AppType::ZOOM;

    // Discord
    if (s.find("discord")    != std::string::npos ||
        s.find("discordapp") != std::string::npos)
        return AppType::DISCORD;

    // GitHub
    if (s.find("github")          != std::string::npos ||
        s.find("githubusercontent") != std::string::npos)
        return AppType::GITHUB;

    // Cloudflare
    if (s.find("cloudflare") != std::string::npos)
        return AppType::CLOUDFLARE;

    // SNI present but unrecognised → generic HTTPS
    return AppType::HTTPS;
}

} // namespace NetScope
