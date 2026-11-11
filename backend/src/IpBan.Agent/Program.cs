using IpBan.Agent;
using IpBan.Agent.Options;
using IpBan.Agent.Service;
using IpBan.Agent.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Logging.Syslog;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddIpBanFileLogging(builder.Configuration, builder.Environment.ContentRootPath);
builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));
builder.Services.AddIpBanIdGeneration();
builder.Services.AddIpBanPersistence();
builder.Services.AddSingleton<ISyslogSettingsReader, AgentSyslogSettingsReader>();
builder.Services.AddIpBanSyslog(builder.Logging, "agent",
    Path.GetFullPath(builder.Configuration["Agent:DataDirectory"] ?? "data", builder.Environment.ContentRootPath),
    builder.Configuration["Syslog:ComputerName"]);
builder.Services.AddIpBanFirewallProviders();
builder.Services.AddIpBanAgentIpc();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
