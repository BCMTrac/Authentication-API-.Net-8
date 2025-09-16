using System.Net;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.DTOs;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Microsoft.AspNetCore.Identity;
using System; // Added for DateTimeOffset and Guid

